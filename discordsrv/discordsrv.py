import asyncio
import uuid
import mysql.connector
from os import name
import discord
from redbot.core import commands
from redbot.core import Config
from redbot.core.commands.commands import Command
from .core.database import Database
from redbot.core.utils.predicates import MessagePredicate
import requests
import datetime

class DiscordSRV(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.config = Config.get_conf(self, identifier=770929133085655060, force_registration=True)
        default_guild = {
            "enabled": "False",
            "database":{
                "host": None,
                "port": None,
                "user": None,
                "password": None,
                "database": None
            }
        }
        self.config.register_guild(**default_guild)

    @staticmethod
    async def get_linked(self, member_id: int, db_config: dict):
        mydb = mysql.connector.connect(**db_config)
        mycursor = mydb.cursor(dictionary=True)
        sql = "SELECT * FROM discordsrv_accounts WHERE discord ='{}'".format(member_id)
        mycursor.execute(sql)
        myresult = mycursor.fetchall()
        mydb.close()
        return myresult

    @staticmethod
    async def delete_quietly(message: discord.Message):
        try:
            await message.delete()
        except discord.HTTPException:
            pass

    async def send_and_query_response(
        self,
        ctx: commands.Context,
        query: str,
        pred: MessagePredicate = None,
        *,
        timeout: int = 60
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

    # https://api.mojang.com/user/profiles/<uuid>/names
    @staticmethod
    async def get_name(uuid):
        url = f"https://api.mojang.com/user/profiles/{uuid}/names"
        r = requests.get(url)
        return r.json()[-1]["name"]

    @commands.guild_only()
    @commands.group(aliases=["dsrv"])
    async def discordsrv(self, ctx: commands.Context):
        """WIP"""

    @discordsrv.command(name="linked")
    async def dsrv_linked(self, ctx: commands.Context, member: discord.Member):
        em = discord.Embed()
        """Get linked account details"""
        enabled = await self.config.guild(ctx.guild).get_raw("enabled")
        if (enabled == "True") :
            async with ctx.typing():
                linked_data = await self.get_linked(self, member_id=member.id, db_config=await self.config.guild(member.guild).get_raw("database"))
                if (linked_data == []):
                    em.color = member.color
                    em.description = member.mention + " 未綁定 Minecraft 帳號！"
                else:
                    mc_name = await self.get_name(linked_data[0]["uuid"])
                    em.color = member.color
                    em.description = member.mention
                    em.add_field(name="Minecraft Name", value="```fix\n"+mc_name+"\n```" , inline=False)
                    em.add_field(name="UUID", value="```yaml\n"+linked_data[0]["uuid"]+"\n```" , inline=False)
                    em.set_footer(text=str(linked_data[0]["link"]))
                    # set em timestamp = now
                    em.timestamp = datetime.datetime.utcnow()
                    em.set_author(name=member, icon_url=member.avatar_url)
                    em.set_thumbnail(url=f"https://cravatar.eu/head/{linked_data[0]['uuid']}/128.png")
                    em.set_author(name=str(member)+" 已綁定 Minecraft 帳號！", icon_url=member.avatar_url)
                await ctx.send(embed=em)

    @commands.admin()
    @discordsrv.group(name="set")
    async def dsrv_set(self, ctx):
        """Setting discordSRV database"""
        pass

    @dsrv_set.command(name="host")
    async def dsrv_set_host(self, ctx: commands.Context):
        """set the database host(e.g. `domain.com`, `123.45.67.8`) of discordSRV"""
        #regex for hostname and ip address: https://regex101.com/r/0WMysi/2
        pred = MessagePredicate.regex(
            pattern="^(((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|((([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)+([A-Za-z|[A-Za-z][A-Za-z0-9\\‌​-]*[A-Za-z0-9])))$"
            )
        try:
            result = await self.send_and_query_response(
                ctx, "Please send the host you want to set: (e.g. `domain.com`, `123.45.67.8`)", pred
            )
        except asyncio.TimeoutError:
            await ctx.send("Query timed out, nothing changed.")
        
        if result is not None:
            await self.config.guild(ctx.guild).set_raw("database", "host", value=result)
            await ctx.send("Database host has been set to {}.".format(result))
    
    @dsrv_set.command(name="port")
    async def dsrv_set_port(self, ctx: commands.Context):
        """set the database port of DiscordSRV"""
        pred = MessagePredicate.regex(
            pattern="^((6553[0-5])|(655[0-2][0-9])|(65[0-4][0-9]{2})|(6[0-4][0-9]{3})|([1-5][0-9]{4})|([0-5]{0,5})|([0-9]{1,4}))$"
        )
        try:
            result = await self.send_and_query_response(
                ctx, "Please send the port you want to set:", pred
            )
        except asyncio.TimeoutError:
            await ctx.send("Query timed out, nothing changed.")
        
        if result is not None:
            await self.config.guild(ctx.guild).set_raw("database", "port", value=result)
            await ctx.send("Database port has been set to {}.".format(result))

    @dsrv_set.command(name="password", aliases=["pswd", "passwd", "ps"])
    async def dsrv_set_pswd(self, ctx: commands.Context):
        """set the database password of DiscordSRV"""
        try:
            result = await self.send_and_query_response(
                ctx, "Please set the password (limit in 32 char):"
            )
        except asyncio.TimeoutError:
            await ctx.send("Query timed out, nothing changed.")

        if result is not None:
            await self.config.guild(ctx.guild).set_raw("database", "password", value=result)
            await ctx.author.send("Database password has been set to {}.".format(result))
            await ctx.tick()

    @dsrv_set.command(name="name")
    async def dsrv_set_table(self, ctx: commands.Context):
        """set the database name that DiscordSRV using"""
        try:
            result = await self.send_and_query_response(
                ctx, "Please input the table name (limit in 64 char):"
            )
        except asyncio.TimeoutError:
            await ctx.send("Query timed out, nothing changed.")

        if result is not None:
            await self.config.guild(ctx.guild).set_raw("database", "database", value=result)
            await ctx.send("DiscordSRV database's name has been set to {}.".format(result))

    @dsrv_set.command(name="user")
    async def dsrv_set_user(self, ctx: commands.Context):
        """set the database login as who"""
        try:
            result = await self.send_and_query_response(
                ctx, "Please input the user name (limit in 16 char):"
            )
        except asyncio.TimeoutError:
            await ctx.send("Query timed out, nothing changed.")

        if result is not None:
            await self.config.guild(ctx.guild).set_raw("database", "user", value=result)
            await ctx.send("DiscordSRV login username has been set to {}.".format(result))
    
    @dsrv_set.command(name="enable", aliases=["on"])
    async def dsrv_set_enabled(self, ctx: commands.Context):
        """enable the fuction"""
        pred = MessagePredicate.yes_or_no()
        try:
            await ctx.send("Are you sure to ENABLE? (Yes to Enable / No to Disable):")
            await self.bot.wait_for("message", check=pred, timeout=60)
        except asyncio.TimeoutError:
            await ctx.send("Query timed out, nothing changed.")

        if pred.result is True:
            await self.config.guild(ctx.guild).set_raw("enabled", value="True")
            await ctx.send("DiscordSRV fuction now is ON.")
        else:
            await self.config.guild(ctx.guild).set_raw("enabled",value="False")
            await ctx.send("DiscordSRV fuction now is OFF.")