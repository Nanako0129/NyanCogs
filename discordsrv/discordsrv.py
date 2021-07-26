import asyncio
import discord
from redbot.core import commands
from redbot.core import Config
from redbot.core.commands.commands import Command
from .core.database import Database
from redbot.core.utils.predicates import MessagePredicate

class DiscordSRV(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.config = Config.get_conf(self, identifier=770929133085655060, force_registration=True)
        default_guild = {
            "enabled": False,
            "database":{
                "db_host": None,
                "db_user": None,
                "db_pswd": None,
                "db_table": None
            }
        }
        self.config.register_guild(**default_guild)

    async def send_and_query_response(
        self,
        ctx: commands.Context,
        query: str,
        pred: MessagePredicate = None,
        *,
        timeout: int = 60,
    ) -> str:
        if pred is None:
            pred = MessagePredicate.same_context(ctx)
        ask = await ctx.send(query)
        try:
            message = await self.bot.wait_for("message", check=pred, timeout=timeout)
        except asyncio.TimeoutError:
            await self.delete_quietly(ask)
            raise
        await self.delete_quietly(ask)
        await self.delete_quietly(message)
        return message.content

    @commands.guild_only()
    @commands.mod()
    @commands.group(aliases=["dsrv"])
    async def discordsrv(self, ctx: commands.Context):
        """WIP"""
        await ctx.send("WIP")

    @discordsrv.command(name="linked")
    async def dsrv_linked(self, ctx: commands.Context, member: discord.member):
        """Get linked account details"""
        is_enabled = await self.config.guild(member.guild).enabled()
        if(is_enabled):
            await ctx.send("OK!")
            linked_data = await Database.get_linked(self.config.guild(member.guild).database())
            if (linked_data == []):
                await ctx.send("NO RESULT!")
            else:
                await ctx.send(linked_data[0])
    
    @commands.admin()
    @discordsrv.group(name="set")
    async def dsrv_set(self, ctx):
        """Setting discordSRV database"""

    async def dsrv_set_host(self, ctx: commands.Context, hostname: str):
        """set the database host(e.g. `domain.com`, `123.45.67.8`) of discordSRV"""
        #regex for hostname and ip address: https://regex101.com/r/0WMysi/2
        pred = MessagePredicate.regex(
            pattern="^(((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|((([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)+([A-Za-z|[A-Za-z][A-Za-z0-9\‌​-]*[A-Za-z0-9])))$"
            )
        try:
            await self.send_and_query_response(
                ctx, "Please send the host you want to set:(e.g. `domain.com`, `123.45.67.8`)", pred
            )
        except asyncio.TimeoutError:
            await ctx.send("Query timed out, nothing changed.")
        
        if pred.result is not NULL:
            await self.config.guild(ctx.guild).set_raw("database", "db_host", value=hostname)
            await ctx.send("Database host has been set to {}.".format(pred.result))
