<?php

declare(strict_types=1);

namespace Rift;

use pocketmine\event\Listener;
use pocketmine\event\player\PlayerCreationEvent;
use pocketmine\player\Player;
use pocketmine\plugin\PluginBase;

/**
 * RiftSupport — drop this plugin into every downstream server behind Rift.
 *
 *  - Swaps the default Player for {@link RiftPlayer} so players get deterministic
 *    entity ids (required for Rift's seamless transfer).
 *  - Warns if a custom Player class is already in use (then add the snippet yourself).
 *  - Warns if packet encryption is still enabled (Rift needs it off).
 *  - (Optional) Out-of-band transfer trigger for the proxy's `lazy_decode` mode: call
 *    {@link Main::transfer()} instead of `$player->transfer()` so the transfer intent reaches the proxy
 *    via its control channel — never as an in-stream TransferPacket. This lets the proxy keep the
 *    steady-state down stream a pure pass-through (no decode). See config.yml.
 */
final class Main extends PluginBase implements Listener{

	private static ?Main $instance = null;

	private bool $warnedCustomPlayer = false;

	/** Out-of-band control channel (mirrors the proxy's [control] section). Empty host = disabled. */
	private string $controlHost = "";
	private int $controlPort = 0;
	private string $controlToken = "";

	/** @var (\Closure(Player, string): void)|null Optional pre-transfer save hook (cross-server data flush). */
	private ?\Closure $saveHandler = null;

	protected function onEnable() : void{
		self::$instance = $this;
		$this->saveDefaultConfig();
		$cfg = $this->getConfig();
		$this->controlHost = (string) $cfg->getNested("control.host", "");
		$this->controlPort = (int) $cfg->getNested("control.port", 0);
		$this->controlToken = (string) $cfg->getNested("control.token", "");

		// Rift forwards traffic in plaintext; encryption on the downstream breaks it.
		if($this->getServer()->getConfigGroup()->getPropertyBool("network.enable-encryption", true)){
			$this->getLogger()->warning(
				"Rift requires 'network.enable-encryption: false' in pocketmine.yml — " .
				"transfers will NOT work until you disable it and restart."
			);
		}

		$this->getServer()->getPluginManager()->registerEvents($this, $this);
		if($this->controlEnabled()){
			$this->getLogger()->info(
				"RiftSupport enabled — deterministic entity ids + out-of-band control ({$this->controlHost}:{$this->controlPort}). " .
				"Call Rift\\Main::transfer(\$player, \$channel) instead of \$player->transfer()."
			);
		}else{
			$this->getLogger()->info("RiftSupport enabled — players will receive deterministic entity ids.");
		}
	}

	protected function onDisable() : void{
		self::$instance = null;
	}

	public function onPlayerCreation(PlayerCreationEvent $event) : void{
		// Only override the *default* Player. If another plugin/core already set a
		// custom Player class, don't clobber it — tell the admin to add the snippet.
		if($event->getPlayerClass() === Player::class){
			$event->setPlayerClass(RiftPlayer::class);
		}elseif(!$this->warnedCustomPlayer){
			$this->warnedCustomPlayer = true;
			$this->getLogger()->warning(
				"A custom Player class ({$event->getPlayerClass()}) is in use; RiftSupport will not replace it. " .
				"Add the crc32(XUID) snippet to that class' initEntity() — see the Rift README."
			);
		}
	}

	/** Whether the out-of-band control channel is configured (host + port + token all set). */
	public function controlEnabled() : bool{
		return $this->controlHost !== "" && $this->controlPort > 0 && $this->controlToken !== "";
	}

	/**
	 * Register a callback run synchronously, just before an out-of-band transfer, to persist the
	 * player's cross-server data (DB flush, etc.). It runs BEFORE the proxy connects the player to the
	 * destination, so the new server loads fresh data.
	 *
	 * Note: this backend's PlayerQuitEvent still fires later, when the proxy drops this connection after
	 * the swap — so anything you already do on quit keeps working; this hook only fixes *ordering*.
	 */
	public static function setSaveHandler(\Closure $handler) : void{
		if(self::$instance !== null){
			self::$instance->saveHandler = $handler;
		}
	}

	/**
	 * Seamless transfer via the out-of-band control channel — for the proxy's `lazy_decode` mode.
	 * Call this INSTEAD of `$player->transfer()`: it must NOT emit a client-facing TransferPacket
	 * (in lazy mode the proxy would forward it raw and the client would try to reach the channel name).
	 *
	 * Steps: (1) despawn this server's entities from the player's view so nothing ghosts on the
	 * destination (the proxy no longer tracks them in lazy mode); (2) run the save hook + local save;
	 * (3) signal the proxy. The proxy then connects to the destination and drops this connection,
	 * which fires the normal PlayerQuitEvent here for backend cleanup.
	 *
	 * Returns false if the control channel is not configured — callers should fall back to
	 * `$player->transfer($host, $port)` (legacy in-stream path).
	 *
	 * @param string $channel destination channel name (a key in the proxy's [servers] map).
	 */
	public static function transfer(Player $player, string $channel) : bool{
		$self = self::$instance;
		if($self === null || !$self->controlEnabled()){
			return false;
		}
		// 1) Clear this server's entities from the player's view (proxy doesn't track them in lazy mode).
		foreach($player->getWorld()->getEntities() as $e){
			if($e !== $player){
				$e->despawnFrom($player);
			}
		}
		// 2) Persist before the destination loads the player (cross-server data ordering).
		if($self->saveHandler !== null){
			($self->saveHandler)($player, $channel);
		}
		$player->save();
		// 3) Trigger the seamless transfer out-of-band (no game-stream packet reaches the client).
		return $self->sendControl("transfer " . $player->getName() . " " . $channel);
	}

	/** Force-disconnect a player from the network via the proxy control channel. */
	public static function kick(Player $player) : bool{
		$self = self::$instance;
		if($self === null || !$self->controlEnabled()){
			return false;
		}
		return $self->sendControl("kick " . $player->getName());
	}

	/**
	 * Sends one command line to the proxy control channel and checks the reply. Best-effort with a short
	 * timeout (the channel is localhost). Blocking, but transfers are infrequent and the peer is local.
	 */
	private function sendControl(string $command) : bool{
		$errno = 0;
		$errstr = "";
		$sock = @stream_socket_client("tcp://{$this->controlHost}:{$this->controlPort}", $errno, $errstr, 1.0);
		if($sock === false){
			$this->getLogger()->warning("Rift control connect failed ({$this->controlHost}:{$this->controlPort}): {$errstr}");
			return false;
		}
		stream_set_timeout($sock, 1);
		@fwrite($sock, $this->controlToken . " " . $command . "\n");
		$reply = @fgets($sock); // one-line ack; non-fatal if it times out
		@fclose($sock);
		if(is_string($reply) && strncmp($reply, "ok", 2) !== 0){
			$this->getLogger()->warning("Rift control rejected '{$command}': " . trim($reply));
			return false;
		}
		return true;
	}
}
