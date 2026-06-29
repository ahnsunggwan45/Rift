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
 */
final class Main extends PluginBase implements Listener{

	private bool $warnedCustomPlayer = false;

	protected function onEnable() : void{
		// Rift forwards traffic in plaintext; encryption on the downstream breaks it.
		if($this->getServer()->getConfigGroup()->getPropertyBool("network.enable-encryption", true)){
			$this->getLogger()->warning(
				"Rift requires 'network.enable-encryption: false' in pocketmine.yml — " .
				"transfers will NOT work until you disable it and restart."
			);
		}

		$this->getServer()->getPluginManager()->registerEvents($this, $this);
		$this->getLogger()->info("RiftSupport enabled — players will receive deterministic entity ids.");
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
}
