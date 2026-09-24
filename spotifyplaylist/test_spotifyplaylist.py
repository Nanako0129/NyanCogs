import asyncio
import json
import unittest

from spotifyplaylist import spotifyplaylist as sp

PLAYLIST_URL = "https://api.spotify.com/v1/playlists/0SfYiKmJyx8TM5Ruuzxngd/tracks"


def embed_html(track_list):
    data = {"props": {"pageProps": {"state": {"data": {"entity": {"trackList": track_list}}}}}}
    return f'<html><script id="__NEXT_DATA__" type="application/json">{json.dumps(data)}</script></html>'


TRACKS = [
    {"uri": "spotify:track:1Hx1aiBurYo0000000000a", "title": "amnesia", "subtitle": "Aiobahn,\xa0rionos"},
    {"uri": "spotify:episode:xyz", "title": "a podcast", "subtitle": "someone"},
    {"uri": "spotify:local:::", "title": "local file", "subtitle": ""},
]


class ParseEmbedTest(unittest.TestCase):
    def test_tracks_get_the_fields_audio_reads(self):
        items = sp.parse_embed(embed_html(TRACKS))
        self.assertEqual(len(items), 1)  # episode and local file dropped
        track = items[0]["track"]
        self.assertEqual(track["name"], "amnesia")
        self.assertEqual(track["artists"][0]["name"], "Aiobahn")
        self.assertEqual(track["id"], "1Hx1aiBurYo0000000000a")
        self.assertEqual(track["uri"], "spotify:track:1Hx1aiBurYo0000000000a")
        self.assertEqual(track["type"], "track")
        self.assertEqual(track["external_urls"]["spotify"], "https://open.spotify.com/track/1Hx1aiBurYo0000000000a")

    def test_unparseable_page_is_empty(self):
        self.assertEqual(sp.parse_embed("<html>nothing</html>"), [])
        self.assertEqual(sp.parse_embed('<script id="__NEXT_DATA__" type="application/json">{}</script>'), [])
        self.assertEqual(len(sp.parse_embed(embed_html([None, "x", 3] + TRACKS))), 1)  # non-object entries skipped
        self.assertEqual(sp.parse_embed(embed_html({"not": "a list"})), [])
        null_entity = {"props": {"pageProps": {"state": {"data": {"entity": None}}}}}
        self.assertEqual(sp.parse_embed(f'<script id="__NEXT_DATA__" type="application/json">{json.dumps(null_entity)}</script>'), [])


class FetchEmbedTest(unittest.TestCase):
    def fetch(self, entries):
        class Resp:
            status = 200

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def text(self):
                return embed_html(entries)

        class Session:
            def get(self, *args, **kwargs):
                return Resp()

        return asyncio.run(sp.fetch_embed_items(Session(), "0SfYiKmJyx8TM5Ruuzxngd"))

    def test_possibly_cut_list_is_reported_from_the_raw_count(self):
        # Spotify dropped two unavailable tracks from a 258-track playlist and listed 98: still a cut list.
        entries = [dict(TRACKS[0], uri=f"spotify:track:{i:022d}") for i in range(98)]
        with self.assertLogs(sp.log, "WARNING") as logs:
            self.assertEqual(len(self.fetch(entries)), 98)
        self.assertIn("may be cut at 100", logs.output[0])

    def test_short_list_is_not_reported(self):
        with self.assertNoLogs(sp.log, "WARNING"):
            self.assertEqual(len(self.fetch(TRACKS)), 1)


class PatchTest(unittest.TestCase):
    def make_api(self, response):
        class FakeAPI:
            session = None

            async def make_get_call(self, url, params=None):
                return response

        sp._patch(FakeAPI)
        return FakeAPI

    def run_call(self, api_cls, url, embed_items):
        async def fake_fetch(session, playlist_id):
            self.fetched = playlist_id
            return embed_items

        self.fetched = None
        original_fetch, sp.fetch_embed_items = sp.fetch_embed_items, fake_fetch
        try:
            return asyncio.run(api_cls().make_get_call(url, {}))
        finally:
            sp.fetch_embed_items = original_fetch

    def test_forbidden_playlist_falls_back_to_embed(self):
        api = self.make_api({"error": {"status": 403, "message": "Forbidden"}})
        items = sp.parse_embed(embed_html(TRACKS))
        result = self.run_call(api, PLAYLIST_URL, items)
        self.assertEqual(self.fetched, "0SfYiKmJyx8TM5Ruuzxngd")
        self.assertEqual(result, {"items": items, "total": 1, "next": None})

    def test_successful_and_non_playlist_calls_pass_through(self):
        ok = {"items": [], "total": 0, "next": None}
        self.assertIs(self.run_call(self.make_api(ok), PLAYLIST_URL, [{}]), ok)
        err = {"error": {"status": 403}}
        album = "https://api.spotify.com/v1/albums/0SfYiKmJyx8TM5Ruuzxngd/tracks"
        self.assertIs(self.run_call(self.make_api(err), album, [{}]), err)
        self.assertIsNone(self.fetched)

    def test_empty_embed_keeps_the_original_error(self):
        err = {"error": {"status": 403}}
        self.assertIs(self.run_call(self.make_api(err), PLAYLIST_URL, []), err)

    def test_embed_network_failure_keeps_the_original_error(self):
        async def failing_fetch(session, playlist_id):
            raise asyncio.TimeoutError

        err = {"error": {"status": 403}}
        api = self.make_api(err)
        original_fetch, sp.fetch_embed_items = sp.fetch_embed_items, failing_fetch
        try:
            self.assertIs(asyncio.run(api().make_get_call(PLAYLIST_URL, {})), err)
        finally:
            sp.fetch_embed_items = original_fetch

    def test_patch_is_idempotent_and_reversible(self):
        api = self.make_api({})
        wrapped = api.make_get_call
        sp._patch(api)
        self.assertIs(api.make_get_call, wrapped)
        sp._unpatch(api)
        self.assertIsNot(api.make_get_call, wrapped)
        self.assertFalse(hasattr(api, sp._PATCH_FLAG))


if __name__ == "__main__":
    unittest.main()
