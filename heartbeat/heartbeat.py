"""Heartbeat cog for Red-DiscordBot by PhasecoreX."""
import asyncio
import logging
from datetime import timedelta

import aiohttp
from redbot.core import Config
from redbot.core import __version__ as redbot_version
from redbot.core import checks, commands
from redbot.core.utils.chat_formatting import humanize_timedelta

from .pcx_lib import SettingDisplay, checkmark, delete

user_agent = (
    f"Red-DiscordBot/{redbot_version} Heartbeat (https://github.com/PhasecoreX/PCXCogs)"
)
log = logging.getLogger("red.pcxcogs.heartbeat")


class Heartbeat(commands.Cog):
    """Monitor your bots uptime.

    The bot owner can specify a URL that the bot will ping (send a GET request)
    at a configurable frequency. Using this with an uptime tracking service can
    warn you when your bot isn't connected to the internet (and thus usually
    not connected to Discord).
    """

    __author__ = "PhasecoreX"
    __version__ = "1.1.0"

    default_global_settings = {"url": "", "frequency": 60}

    def __init__(self, bot):
        """Set up the cog."""
        super().__init__()
        self.bot = bot
        self.config = Config.get_conf(
            self, identifier=1224364860, force_registration=True
        )
        self.config.register_global(**self.default_global_settings)
        self.session = aiohttp.ClientSession()
        self.bg_loop_task = None

    #
    # Red methods
    #

    def cog_unload(self):
        """Clean up when cog shuts down."""
        if self.bg_loop_task:
            self.bg_loop_task.cancel()
        asyncio.create_task(self.session.close())

    def format_help_for_context(self, ctx: commands.Context) -> str:
        """Show version in help."""
        pre_processed = super().format_help_for_context(ctx)
        return f"{pre_processed}\n\nCog Version: {self.__version__}"

    async def red_delete_data_for_user(
        self, **kwargs
    ):  # pylint: disable=unused-argument
        """Nothing to delete."""
        return

    #
    # Initialization methods
    #

    async def initialize(self):
        """Perform setup actions before loading cog."""
        self.enable_bg_loop()

    #
    # Background loop methods
    #

    def enable_bg_loop(self):
        """Set up the background loop task."""

        def error_handler(fut: asyncio.Future):
            try:
                fut.result()
            except asyncio.CancelledError:
                pass
            except Exception as exc:  # pylint: disable=broad-except
                log.exception(
                    "Unexpected exception occurred in background loop of Heartbeat: ",
                    exc_info=exc,
                )
                asyncio.create_task(
                    self.bot.send_to_owners(
                        "An unexpected exception occurred in the background loop of Heartbeat.\n"
                        "Heartbeat pings will not be sent until Heartbeat is reloaded.\n"
                        "Check your console or logs for details, and consider opening a bug report for this."
                    )
                )

        if self.bg_loop_task:
            self.bg_loop_task.cancel()
        self.bg_loop_task = self.bot.loop.create_task(self.bg_loop())
        self.bg_loop_task.add_done_callback(error_handler)

    async def bg_loop(self):
        """Background loop."""
        await self.bot.wait_until_ready()
        frequency = await self.config.frequency()
        if frequency < 60:
            frequency = 60.0
        while True:
            await self.send_heartbeat()
            await asyncio.sleep(frequency)

    async def send_heartbeat(self):
        """Send a heartbeat ping."""
        url = await self.config.url()
        url = url + str(round(self.bot.latency * 1000)) #send ws latency to uptime kura
        if url:
            retries = 3
            while retries > 0:
                try:
                    await self.session.get(
                        url,
                        headers={"user-agent": user_agent},
                    )
                    break
                except (
                    aiohttp.ClientConnectionError,
                    asyncio.TimeoutError,
                ):
                    pass
                retries -= 1

    #
    # Command methods: heartbeat
    #

    @commands.group()
    @checks.is_owner()
    async def heartbeat(self, ctx: commands.Context):
        """Manage Heartbeat settings."""

    @heartbeat.command()
    async def settings(self, ctx: commands.Context):
        """Display current settings."""
        global_section = SettingDisplay("Global Settings")
        global_section.add(
            "Heartbeat",
            "Enabled" if await self.config.url() else "Disabled (no URL set)",
        )
        global_section.add(
            "Frequency", humanize_timedelta(seconds=await self.config.frequency())
        )
        await ctx.send(str(global_section))

    @heartbeat.command()
    async def url(self, ctx: commands.Context, url: str):
        """Set the URL Heartbeat will send pings to."""
        await delete(ctx.message)
        await self.config.url.set(url)
        await ctx.send(checkmark("Heartbeat URL has been set and enabled."))
        self.enable_bg_loop()

    @heartbeat.command()
    async def frequency(
        self,
        ctx: commands.Context,
        frequency: commands.TimedeltaConverter(
            minimum=timedelta(seconds=60),
            maximum=timedelta(days=30),
            default_unit="seconds",  # noqa: F821
        ),
    ):
        """Set the frequency Heartbeat will send pings."""
        await self.config.frequency.set(frequency.total_seconds())
        await ctx.send(
            checkmark(
                f"Heartbeat frequency has been set to {humanize_timedelta(timedelta=frequency)}."
            )
        )
        self.enable_bg_loop()
