import asyncio
import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import lavalink

from netstat import netstat as ns

SNMP_TEXT = """Ip: Forwarding DefaultTTL InReceives
Ip: 1 64 100
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors
Udp: 10 0 0 123456 0 0 0 0 0
UdpLite: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors
UdpLite: 0 0 0 0 0 0 0 0 0
"""


def node(ready=True, sent=3000, nulled=0, deficit=0):
    return SimpleNamespace(
        ready=ready,
        stats=SimpleNamespace(frames_sent=sent, frames_nulled=nulled, frames_deficit=deficit),
    )


def player(guild_id):
    return SimpleNamespace(guild=SimpleNamespace(id=guild_id))


def lavalink_state(nodes, players):
    return (
        patch.object(ns.lavalink, "get_all_nodes", return_value=nodes),
        patch.object(ns.lavalink, "active_players", return_value=tuple(players)),
    )


class ParseTest(unittest.TestCase):
    def test_udp_out_is_read_from_the_udp_value_line(self):
        self.assertEqual(ns.parse_udp_out(SNMP_TEXT), 123456)  # not the UdpLite line

    def test_unparseable_snmp_is_none(self):
        self.assertIsNone(ns.parse_udp_out(""))
        self.assertIsNone(ns.parse_udp_out("Udp: InDatagrams\nUdp: 1\n"))

    def test_rate_needs_two_ordered_samples(self):
        self.assertEqual(ns.udp_rate((0.0, 100), (2.0, 200)), 50.0)
        self.assertIsNone(ns.udp_rate(None, (2.0, 200)))  # first sample after load
        self.assertIsNone(ns.udp_rate((0.0, 100), None))
        self.assertIsNone(ns.udp_rate((2.0, 100), (2.0, 200)))
        self.assertIsNone(ns.udp_rate((0.0, 300), (2.0, 200)))  # counter went backwards

    def test_ping_from_raw_player_update(self):
        self.assertEqual(ns.ping_from({"state": {"position": 1, "ping": 23}}), 23)
        self.assertIsNone(ns.ping_from({"state": {"position": 1}}))  # Lavalink without ping
        self.assertIsNone(ns.ping_from({"state": {"ping": -1}}))  # not connected
        self.assertIsNone(ns.ping_from({"state": {"ping": True}}))
        self.assertIsNone(ns.ping_from({}))


class SnapshotTest(unittest.TestCase):
    def test_unknown_values_become_none_and_json_stays_valid(self):
        a, b = lavalink_state([node(sent=-1, nulled=-1, deficit=-1)], [player(1)])
        with a, b:
            snap = ns.snapshot(float("inf"), {}, 0.0)
        self.assertIsNone(snap["gateway_ms"])
        self.assertIsNone(snap["frames_sent"])
        self.assertIsNone(snap["voice_ping_ms"])
        body = json.loads(ns.heartbeat_body(snap, None, 1))  # heartbeat_body uses allow_nan=False
        self.assertIsNone(body["udp_out_per_s"])

    def test_nan_latency_is_none(self):
        a, b = lavalink_state([], [])
        with a, b:
            snap = ns.snapshot(float("nan"), {}, 0.0)
        self.assertEqual(snap, {
            "gateway_ms": None, "lavalink_ready": False, "playing": 0, "voice_ping_ms": None,
            "frames_sent": None, "frames_nulled": None, "frames_deficit": None,
        })

    def test_live_players_count_and_worst_ping(self):
        a, b = lavalink_state([node()], [player(1), player(2)])
        with a, b:
            snap = ns.snapshot(0.0423, {1: (20, 98.0), 2: (35, 99.0), 3: (900, 99.0)}, 100.0)  # guild 3 not playing
        self.assertEqual(snap["gateway_ms"], 42)
        self.assertEqual(snap["playing"], 2)
        self.assertEqual(snap["voice_ping_ms"], 35)
        self.assertEqual(snap["frames_sent"], 3000)

    def test_stale_ping_and_disconnected_node_stats_are_ignored(self):
        a, b = lavalink_state([node(ready=False, sent=3000), node(sent=2900)], [player(1)])
        with a, b:
            snap = ns.snapshot(0.01, {1: (900, 0.0)}, 16.0)  # ping from a past session
        self.assertIsNone(snap["voice_ping_ms"])
        self.assertEqual(snap["frames_sent"], 2900)  # the ready node, not the dead one's last stats
        self.assertTrue(snap["lavalink_ready"])

    def test_webhook_scheme_rules(self):
        self.assertTrue(ns.webhook_allowed("https://n8n.example/webhook/x"))
        self.assertTrue(ns.webhook_allowed("http://100.68.132.79:5678/webhook/x"))  # tailnet
        self.assertTrue(ns.webhook_allowed("http://192.168.1.2/webhook/x"))
        self.assertFalse(ns.webhook_allowed("http://n8n.example/webhook/x"))  # hostname over plain http
        self.assertFalse(ns.webhook_allowed("http://8.8.8.8/webhook/x"))
        self.assertFalse(ns.webhook_allowed("n8n.example/webhook/x"))
        self.assertFalse(ns.webhook_allowed("https:///nohost"))
        self.assertFalse(ns.webhook_allowed("http://[::1/webhook/x"))  # urlsplit ValueError
        self.assertFalse(ns.webhook_allowed("https://n8n.example:99999/x"))  # port out of range

    def test_embed_shows_expected_rate_and_finish(self):
        a, b = lavalink_state([node()], [player(1)])
        with a, b:
            snap = ns.snapshot(0.01, {}, 0.0)
        live = ns.build_embed(snap, 49.96, 120.4)
        fields = {f.name: f.value for f in live.fields}
        self.assertEqual(fields["UDP sent"], "50.0/s (expect 50/s)")
        self.assertEqual(fields["Voice WS ping"], "N/A")
        self.assertIn("120 s left", live.footer.text)
        self.assertEqual(ns.build_embed(snap, None, 0.3).footer.text, "Finished")


class CogLifecycleTest(unittest.IsolatedAsyncioTestCase):
    def make_cog(self, latency=float("inf"), webhook="https://n8n.test/webhook/x"):
        with patch.object(ns, "Config") as config:
            cog = ns.NetStat(SimpleNamespace(latency=latency, wait_until_red_ready=AsyncMock()))
        cog.config = config.get_conf.return_value
        cog.config.webhook = AsyncMock(return_value=webhook)
        cog.config.webhook.set = AsyncMock()
        return cog

    def make_ctx(self, delete_error=None):
        message = SimpleNamespace(delete=AsyncMock(side_effect=delete_error))
        return SimpleNamespace(message=message, send=AsyncMock())

    async def test_webhook_message_is_deleted_before_validation(self):
        cog = self.make_cog()
        ctx = self.make_ctx()
        await cog.netstatset_webhook.callback(cog, ctx, "http://n8n.example/webhook/secret")
        ctx.message.delete.assert_awaited_once()  # refused URL still leaves the channel
        cog.config.webhook.set.assert_not_awaited()
        self.assertIn("Use an https URL", ctx.send.call_args.args[0])

    async def test_failed_delete_is_reported(self):
        cog = self.make_cog()
        ctx = self.make_ctx(delete_error=ns.discord.Forbidden(MagicMock(status=403), "no perms"))
        await cog.netstatset_webhook.callback(cog, ctx, "https://n8n.example/webhook/secret")
        cog.config.webhook.set.assert_awaited_once_with("https://n8n.example/webhook/secret")
        self.assertIn("delete it yourself", ctx.send.call_args.args[0])

    async def test_netstat_stops_and_finishes_on_unload(self):
        cog = self.make_cog(latency=0.01)
        message = SimpleNamespace(edit=AsyncMock())
        ctx = SimpleNamespace(send=AsyncMock(return_value=message))

        async def unload_during_sleep(_):
            cog._closed = True

        a, b = lavalink_state([], [])
        with a, b, patch.object(ns.asyncio, "sleep", unload_during_sleep):
            await cog.netstat.callback(cog, ctx, 900)
        self.assertEqual(message.edit.await_args.kwargs["embed"].footer.text, "Finished")

    async def test_load_registers_listener_and_unload_stops_everything(self):
        cog = self.make_cog()
        response = MagicMock(status=200)
        post = MagicMock()
        post.return_value.__aenter__ = AsyncMock(return_value=response)
        post.return_value.__aexit__ = AsyncMock(return_value=False)
        a, b = lavalink_state([], [])
        with a, b, patch.object(ns, "HEARTBEAT_EVERY", 0.01):
            await cog.cog_load()
            session = cog._session
            cog._session = SimpleNamespace(post=post, close=session.close)
            self.assertIn(cog._on_player_update, lavalink.lavalink._update_listeners)
            await cog._on_player_update(player(7), None, {"state": {"ping": 12}})
            self.assertEqual(cog._pings[7][0], 12)
            await asyncio.sleep(0.05)
            self.assertGreater(post.call_count, 1)  # the loop really beats
            await cog.cog_unload()
            beats = post.call_count
            await asyncio.sleep(0.05)
        self.assertEqual(post.call_count, beats)  # and stops on unload
        self.assertNotIn(cog._on_player_update, lavalink.lavalink._update_listeners)
        self.assertTrue(session.closed)
        self.assertTrue(cog._task.cancelled())

    async def test_heartbeat_posts_valid_json_while_gateway_is_down(self):
        cog = self.make_cog()
        response = MagicMock(status=200)
        post = MagicMock()
        post.return_value.__aenter__ = AsyncMock(return_value=response)
        post.return_value.__aexit__ = AsyncMock(return_value=False)
        cog._session = SimpleNamespace(post=post)
        a, b = lavalink_state([node()], [player(1)])
        with a, b, patch.object(ns.asyncio, "sleep", AsyncMock(side_effect=asyncio.CancelledError)):
            with self.assertRaises(asyncio.CancelledError):
                await cog._heartbeat()
        url = post.call_args.args[0]
        body = json.loads(post.call_args.kwargs["data"])
        self.assertEqual(url, "https://n8n.test/webhook/x")
        self.assertIs(post.call_args.kwargs["allow_redirects"], False)
        cog.bot.wait_until_red_ready.assert_awaited_once()
        self.assertIsNone(body["gateway_ms"])
        self.assertIsNone(body["udp_out_per_s"])  # first beat has no previous sample
        self.assertEqual(body["playing"], 1)


if __name__ == "__main__":
    unittest.main()
