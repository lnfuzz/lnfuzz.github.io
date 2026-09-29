---
title: "Eclair exhausts CPU and memory from a race that orphans channel actors"
id: LNF-2026-0003
aliases: ["/advisories/lnf-2026-0003/"]
description: "Eclair v0.14.0 and earlier have a TOCTOU race that can cause channel actors to be leaked, and repeated execution of the race leaks memory until the JVM crashes or the garbage collector pegs every core."
date: 2026-09-30
found_with: smite
severity: low
targets:
  - impl: eclair
    affected: "v0.14.0 and earlier"
    fixed_in: "v0.14.1"
    reported: 2026-07-15
    fix: https://github.com/ACINQ/eclair/pull/3324
authors: [matt]
tags: [eclair, dos, race, bolt2]
---

Eclair v0.14.0 and earlier reject a duplicate `temporary_channel_id` by consulting the peer's channel map to see if the `temporary_channel_id` already corresponds to another channel.
But there is a delay between this check and the later insertion of the new channel into the map.
An attacker that pipelines several identical `open_channel` messages can slip two of them past the check, causing Eclair to spawn two channel actors for one `temporary_channel_id`.
The second actor overwrites the first in the channel map, leaving an **orphaned** channel actor that holds roughly **25 KB** of heap until the peer disconnects.
An attacker repeatedly exploiting the race causes Eclair to leak about **1 MB per second**, eventually causing a JVM out-of-memory crash or a garbage-collection death spiral that pegs every core and takes the node off the network.

Upgrade to [Eclair v0.14.1](https://github.com/ACINQ/eclair/releases/tag/v0.14.1) or later.

## Background

A node that receives an `open_channel` message becomes the *fundee* of a new channel.
Both sides identify the new channel by a `temporary_channel_id` chosen by the opener until a real `channel_id` is later derived from the funding outpoint.
BOLT 2 [requires](https://github.com/lightning/bolts/blob/1aadb719b4007c4cea0ba6e36b08c4fb53788dee/02-peer-protocol.md?plain=1#L803) the opener to pick a `temporary_channel_id` that is unused with that peer, and Eclair tries to enforce this requirement.

But Eclair's handling of an incoming `open_channel` has multiple steps.
Eclair's [`Peer`](https://github.com/ACINQ/eclair/blob/7fb9460183490260537c2e80c0ce4f1af144ea90/eclair-core/src/main/scala/fr/acinq/eclair/io/Peer.scala#L241-L249) actor first checks the `temporary_channel_id`, then hands the request to a separately spawned `OpenChannelInterceptor`, which makes an **asynchronous** round trip through the `PendingChannelsRateLimiter` and the `Router` before the `Peer` finally spawns the channel actor and records it.

## The vulnerability

When Eclair v0.14.0 receives `open_channel`, the [`Peer`](https://github.com/ACINQ/eclair/blob/7fb9460183490260537c2e80c0ce4f1af144ea90/eclair-core/src/main/scala/fr/acinq/eclair/io/Peer.scala#L241-L249) does:

```scala
case Event(open: protocol.OpenChannel, d: ConnectedData) =>
  d.channels.get(TemporaryChannelId(open.temporaryChannelId)) match {
    case None =>
      openChannelInterceptor ! OpenChannelNonInitiator(remoteNodeId, Left(open), d.localFeatures, d.remoteFeatures, d.peerConnection.toTyped, d.address)
      stay()
    case Some(_) =>
      log.warning("ignoring open_channel with duplicate temporaryChannelId={}", open.temporaryChannelId)
      stay()
  }
```

The channel map is consulted, and if no duplicate is found, an asynchronous round trip through the interceptor is initiated.
The new `temporary_channel_id` isn't added to the map until the interceptor later [replies](https://github.com/ACINQ/eclair/blob/7fb9460183490260537c2e80c0ce4f1af144ea90/eclair-core/src/main/scala/fr/acinq/eclair/io/Peer.scala#L320):

```scala
stay() using d.copy(channels = d.channels + (TemporaryChannelId(temporaryChannelId) -> channel))
```

The check and delayed insert create a race: two `open_channel` messages with the same `temporary_channel_id`, sent back to back, can both observe `None` at the check and both reach the insertion.
Eclair spawns two channel actors for the `temporary_channel_id`, and each answers with its own `accept_channel`.
The second insertion overwrites the first under the same key, and the first actor becomes orphaned:

- it is no longer in the channel map, so no further channel messages routed through the `Peer` can reach it, and
- it sits in the fundee open state waiting for a `funding_created` that will never arrive.

The interceptor processes one request at a time and rejects any that overlap, so the exploitable window is only the gap between the interceptor sending its reply and the `Peer` processing it.
The window is narrow, but pipelining a small burst of identical copies hits it reliably; in testing each burst had roughly a 50% chance of producing an orphan.

### The orphan is never reaped

An unfunded channel would normally age out.
When it spawns the fundee actor, the `Peer` [schedules](https://github.com/ACINQ/eclair/blob/7fb9460183490260537c2e80c0ce4f1af144ea90/eclair-core/src/main/scala/fr/acinq/eclair/io/Peer.scala#L282) a `TickChannelOpenTimeout`, but the fundee open states do not handle it, so it falls through to the [no-op](https://github.com/ACINQ/eclair/blob/7fb9460183490260537c2e80c0ce4f1af144ea90/eclair-core/src/main/scala/fr/acinq/eclair/channel/fsm/Channel.scala#L2997-L2998) in `whenUnhandled`:

```scala
// peer doesn't cancel the timer
case Event(TickChannelOpenTimeout, _) => stay()
```

The only thing that reaps the orphan is a peer disconnect, so the orphan stays in memory as long as the attacker remains connected.

### The rate limiter does not stop it

The [`PendingChannelsRateLimiter`](https://github.com/ACINQ/eclair/blob/7fb9460183490260537c2e80c0ce4f1af144ea90/eclair-core/src/main/scala/fr/acinq/eclair/io/PendingChannelsRateLimiter.scala) poses an obstacle for this attack, since it limits the number of pending channels to 99, and orphans still count against the limit.

But a key implementation detail allows the attacker to evade this limit.
The `PendingChannelsRateLimiter` tracks pending `temporary_channel_id`s in per-peer vectors and [removes them](https://github.com/ACINQ/eclair/blob/7fb9460183490260537c2e80c0ce4f1af144ea90/eclair-core/src/main/scala/fr/acinq/eclair/io/PendingChannelsRateLimiter.scala#L115-L126) with `filterNot`:

```scala
val pendingChannels1 = pendingChannels.filterNot(_ == channelId)
```

When a `temporary_channel_id` has been admitted more than once, a single removal drops **every** matching entry.
So if the attacker sends a single `error` message for the repeated `temporary_channel_id`, the rate limiter reclaims all matching slots while only the non-orphaned actor actually shuts down.
As a result, the attacker can keep creating orphans unencumbered by the pending-channel limit.

## The attack

An attacker completes the BOLT 8 handshake and `init` exchange as an ordinary peer.
Over a single connection it then repeats the following in a loop:

1. Pick a new `temporary_channel_id`.
2. Send a burst of identical `open_channel` messages using `temporary_channel_id`.
   The burst races the duplicate check, and about half the time a second `open_channel` is accepted, orphaning a channel actor.
3. Send an `error` for that `temporary_channel_id`, freeing every rate-limiter slot while leaving the orphan alive.

The attacker must also read messages sent by Eclair and respond to any `ping`s so that the connection stays open and the orphans cannot be reaped.

### Observed impact

Against an Eclair node with 4 CPU cores, 8 GB of RAM, and a 6 GB JVM heap:

- The heap grew by roughly 1 MB per second, at about 25 KB per orphaned actor.
  The leak rate tapered off over time as Eclair became more overloaded.
- As the heap filled, garbage collection (GC) cycles became more frequent, with CPU use spiking during GC and then subsiding.
  Towards the end of the attack GC ran constantly and pegged all cores.
- After about four hours the node reached one of two end states:
  - the JVM ran out of memory and crashed, or
  - the node froze, unable to process incoming messages, until the attacking peer was eventually disconnected.
    On disconnect, the leaked memory was freed and Eclair was able to recover.

The Eclair node came back on restart or disconnect, and nothing was lost.
The attacker can repeat the attack, but each attempt takes about four hours to reach the end state.
This delay gives Eclair plenty of time to handle on-chain events, so the risk to funds is likely low.

## The fix

[PR #3324](https://github.com/ACINQ/eclair/pull/3324), merged 2026-07-17 and released in v0.14.1, closes the race by [re-checking](https://github.com/ACINQ/eclair/blob/9b0bcec4b1d946b6b1b8c8ba2ae8cf24803bc40e/eclair-core/src/main/scala/fr/acinq/eclair/io/Peer.scala#L269-L276) for a duplicate after the `OpenChannelInterceptor` response arrives, inside the same actor turn that performs the insertion:

```scala
case Event(SpawnChannelNonInitiator(open, channelConfig, channelType, addFunding_opt, localParams, peerConnection), d: ConnectedData) =>
  val temporaryChannelId = open.fold(_.temporaryChannelId, _.temporaryChannelId)
  // Since the channel interceptor step isn't atomic, we must check again that there is no duplicate/conflict.
  d.channels.get(TemporaryChannelId(temporaryChannelId)).orElse(d.channels.get(FinalChannelId(temporaryChannelId))) match {
    case Some(_) =>
      log.warning("ignoring open_channel with duplicate temporaryChannelId={}", temporaryChannelId)
      stay()
    // ...spawn the channel only when the id is still free...
  }
```

Because the `Peer` actor processes one message at a time and the check now shares its turn with the insertion, there is no longer a gap for a second `open_channel` to race through.
The first `open_channel` inserts the channel; the second sees the entry and is dropped, so no orphan is ever created.
And with the race closed there are no duplicate `temporary_channel_id`s for the rate limiter to mishandle.

The same PR also hardened the early duplicate check to compare a `temporary_channel_id` against existing final `channel_id`s, addressing a [related ID-confusion issue](https://erickcestari.dev/blog/eclair-oom-pending-channels/) found by Erick Cestari.

## Discovery

While fuzzing Eclair's funding flow, smite flagged that Eclair would sometimes accept two `open_channel` messages carrying the same `temporary_channel_id`.
Further investigation surfaced the race between the `temporary_channel_id` check and insertion, and experiments confirmed the orphaned actors and memory-exhaustion impact.

## Timeline

- **2026-07-15:** Vulnerability reported privately to ACINQ.
- **2026-07-16:** ACINQ confirmed the issue and added a fix to [PR #3324](https://github.com/ACINQ/eclair/pull/3324).
- **2026-07-17:** Fix merged as [PR #3324](https://github.com/ACINQ/eclair/pull/3324).
- **2026-07-29:** [Eclair v0.14.1](https://github.com/ACINQ/eclair/releases/tag/v0.14.1) released with the fix.
- **2026-09-17:** ACINQ approved public disclosure.
- **2026-09-30:** Public disclosure.

## Takeaways

- **Upgrade to Eclair v0.14.1 or later.**
- **A check and the action it guards must be atomic.**
  A gap between the check and the action lets another event change the state in between, so the check no longer holds when the action runs.
