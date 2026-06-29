<?php

declare(strict_types=1);

namespace Rift;

use pocketmine\nbt\tag\CompoundTag;
use pocketmine\player\Player;

/**
 * Rift-compatible Player.
 *
 * Gives the player's own entity a deterministic runtime id derived from the XUID,
 * so that EVERY downstream server assigns the same player the same id. Rift's
 * seamless transfer relies on this — it means the client's view of "itself" stays
 * consistent across servers and no entity-id rewriting is needed in the proxy.
 *
 * initEntity() runs during construction, before World::addEntity(), so reassigning
 * $this->id here registers the entity under the new id cleanly.
 */
final class RiftPlayer extends Player{

	protected function initEntity(CompoundTag $nbt) : void{
		parent::initEntity($nbt);

		$xuid = $this->getXuid();
		$key = $xuid !== "" ? $xuid : $this->getName(); // offline fallback: name
		$this->id = crc32($key) & 0x7FFFFFFFFFFFFFFF;    // mask -> always positive
	}
}
