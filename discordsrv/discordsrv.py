from os import name
import discord
from redbot.core import commands
from redbot.core import Config
from .core.database import Database

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

    @commands.group(aliases=["dsrv"])
    @commands.guild_only()
    @commands.mod()
    async def discordsrv(self, ctx):
        """WIP"""
        await ctx.send("WIP")

    @discordsrv.command(name="linked")
    async def dsrv_linked(self, ctx, member: discord.member):
        """Get linked account details"""
        is_enabled = await self.config.guild(member.guild).enabled()
        if(is_enabled):
            await ctx.send("OK!")
            linked_data = await Database.get_linked(self.config.guild(member.guild).database())
            if (linked_data == []):
                await ctx.send("NO RESULT!")
            else:
                await ctx.send(linked_data[0])