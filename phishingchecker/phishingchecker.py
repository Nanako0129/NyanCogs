import requests
import discord

from discord.ext import tasks

from redbot.core import Config, commands, modlog
from redbot.core.utils import chat_formatting as cf
from redbot.core.utils.common_filters import URL_RE

phishing_domain_list_url = "https://raw.githubusercontent.com/nikolaischunk/discord-phishing-links/main/domain-list.json"
suspicious_list_url = "https://raw.githubusercontent.com/nikolaischunk/discord-phishing-links/main/suspicious-list.json"

class PhishingChecker(commands.Cog):
    
    def __init__(self, bot):
        self.bot = bot
        self.config = Config.get_conf(self, identifier=360791024465771322503262, force_registration=True)
        default_guild = {
            "enabled": False,
            "send_channel": None,
            "action": None,
            "always_delete": False,
            "unshort_api": None,
        }
        self.config.register_guild(**default_guild)
        self.update_checking_list.start()

    def cog_unload(self):
        self.update_checking_list.cancel()

    @tasks.loop(seconds=1800)
    async def update_checking_list(self) -> None:
        try:
            self.phishing_domain_list = requests.get(phishing_domain_list_url).json()
            self.suspicious_list = requests.get(suspicious_list_url).json()
        except Exception:
            pass
    
    @staticmethod
    async def get_unshort_url(self, url: str, unshort_api: str = None):
        try: 
            r = requests.get(unshort_api.strip("/")+"/api/?url="+url).json()
            return r["longUrl"]
        except Exception:
            r = requests.get("https://unshort.herokuapp.com/api/?url="+url).json()
            return r["longUrl"]

    async def check_phishing_info(self, url: str):
        if url.startswith("https://"):
            url = url[8:]
        elif url.startswith("http://"):
            url = url[7:]
        if url.startswith("www."):
            url = url[4:]
        if url.endswith("/"):
            url = url[:-1]
        if url in self.phishing_domain_list["domains"]:
            return True, "Phishing", url
        if url in self.suspicious_list["domains"]:
            return True, "Suspicious", url
        return False, "", url

    async def send_phishing_warn_embed(
            self,
            message: discord.Message,
            origin_content: str,
            domain: str,
            phishing_type: str,
            channel: discord.TextChannel,
            what_action
        ):
        if what_action == "delete":
            msg_tip = f"~~[Click to jump]({message.jump_url})~~ *The message has been deleted.*"
        else:
            msg_tip = f"[Click to jump]({message.jump_url})"
        embed = discord.Embed(color=await self.bot.get_embed_color(self))
        embed.title = "🔎🔗 • Phishing checker"
        embed.description = f"Phishing message detected!\n The following message contained {cf.bold(phishing_type)} link in our checking list.\n" 
        embed.description += f"{cf.box(origin_content)}\n"
        embed.description += msg_tip
        embed.add_field(name="Username", value=f"`{message.author}`", inline=True)
        embed.add_field(name="ID", value=f"`{message.author.id}`", inline=True)
        embed.add_field(name="Channel", value=f"{message.channel.mention}", inline=True)
        embed.add_field(name="Detected domain", value=f"{cf.box(domain, lang='fix')}", inline=False)
        embed.add_field(name="Action", value="{}".format(cf.box(what_action)), inline=False)
        embed.set_footer(text=f"To disable these notifications, use {cf.inline('[p]phck setch')}")
        await self.bot.get_channel(int(channel)).send(embed=embed)

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if not await self.config.guild(message.guild).get_raw("enabled") and message.author.bot and message.guild is None:
            return
        alaways_delete = await self.config.guild(message.guild).get_raw("always_delete")
        action = await self.config.guild(message.guild).get_raw("action")
        channel_id = await self.config.guild(message.guild).get_raw("send_channel")
        unshort_api = self.config.guild(message.guild).get_raw("unshort_api")
        for match in URL_RE.finditer(message.content):
            url = match.group(0)
            if unshort_api is not None:
                url = await self.get_unshort_url(message, url, unshort_api)
            url = await self.get_unshort_url(message, url)
            is_phishing, phishing_type, match_domain = await self.check_phishing_info(url)
            if is_phishing:
                if channel_id != 0:
                    await self.send_phishing_warn_embed(
                        message=message,
                        origin_content=message.content,
                        domain=match_domain,
                        phishing_type=phishing_type,
                        channel=channel_id,
                        what_action=action
                    )
                if action == "ban":
                    case = await modlog.case_create(
                        self.bot, message.guild, action_type="ban",
                        user=message.author, moderator=self.bot, reason=f"Phishing link detected: {match_domain}")
                elif action == "kick":
                    case = await modlog.case_create(
                        self.bot, message.guild, action_type="kick",
                        user=message.author, moderator=self.bot, reason=f"Phishing link detected: {match_domain}")
                elif action == "delete" or alaways_delete:
                    await message.delete()

    @commands.guild_only()
    @commands.has_permissions(manage_guild=True)
    @commands.bot_has_permissions(manage_messages=True)
    @commands.group(aliases=["phck"])
    async def phishingchecker(self, ctx: commands.Context):
        """Check if the link is phishing"""

    @phishingchecker.command()
    async def enable(self, ctx: commands.Context, on_off: bool):
        """Enable the phishing checker"""
        if on_off:
            if await self.config.guild(ctx.guild).get_raw("enabled") is True:
                await ctx.send("Phishing checker is already enabled.")
                return
            await self.config.guild(ctx.guild).enabled.set(True)
            await ctx.send("Phishing checker enabled")
        else:
            if await self.config.guild(ctx.guild).get_raw("enabled") is False:
                await ctx.send("Phishing checker is already disabled.")
                return
            await self.config.guild(ctx.guild).enabled.set(False)
            await ctx.send("Phishing checker disabled")

    @phishingchecker.command(name="setchannel", aliases=["setch"])
    async def set_send_channel(self, ctx: commands.Context, channel: discord.TextChannel = None):
        """Set the channel to send the phishing checker logs. Leave it blank to disable it."""
        if channel is None:
            await self.config.guild(ctx.guild).send_channel.set(None)
            await ctx.send("Phishing checker logs will not be sent to any channel.")
            return
        await self.config.guild(ctx.guild).set_raw("send_channel", value=str(channel.id))
        await ctx.send(f"Phishing checker logs will be sent to {channel.mention}")

    @phishingchecker.command(name="update", aliases=["up"])
    async def force_update_list(self):
        """Force update the checking list"""
        try:
            self.phishing_domain_list = requests.get(phishing_domain_list_url).json()
            self.suspicious_list = requests.get(suspicious_list_url).json()
        except Exception as e:
            print(e)
        
    @phishingchecker.command(name="action", aliases=["act"])
    async def set_action(self, ctx: commands.Context, action=""):
        """Set the action to take when a phishing link is detected. You can use `ban`, `kick` or `delete`. Leave empty to disable"""
        if action == "":
            await self.config.guild(ctx.guild).set_raw("action", value="")
            await ctx.send("Phishing checker action disabled")
            return
        if action not in ["ban", "kick", "delete"]:
            await ctx.send("Invalid action. Valid actions are ban, kick and delete")
            return
        await self.config.guild(ctx.guild).set_raw("action", value=action)
        await ctx.send("Phishing checker will take action {}".format(action))

    @phishingchecker.command(name="delete", aliases=["del"])
    async def set_always_delete(self, ctx: commands.Context, yes_or_no: bool):
        """Set if the bot should always delete the message when a phishing link is detected"""
        await self.config.guild(ctx.guild).set_raw("always_delete", value=yes_or_no)
        await ctx.send("Phishing checker will {} delete the message".format("" if yes_or_no else "not"))

    @phishingchecker.command(name="showsettings", aliases=["sets"])
    async def show_settings(self, ctx: commands.Context):
        """Show the current settings"""
        enabled = await self.config.guild(ctx.guild).get_raw("enabled")
        action = await self.config.guild(ctx.guild).get_raw("action")
        channel = await self.config.guild(ctx.guild).get_raw("send_channel")
        always_delete = await self.config.guild(ctx.guild).get_raw("always_delete")
        if channel is None:
            channel = "Not set"
        else:
            channel = self.bot.get_channel(int(channel)).mention
        embed = discord.Embed(title="Phishing Checker Settings", color=await self.bot.get_embed_color(self))
        embed.add_field(name="Enabled", value=f"`{enabled}`", inline=False)
        embed.add_field(name="Channel", value=f"{channel}", inline=False)
        embed.add_field(name="Action", value=f"`{action}`", inline=False)
        embed.add_field(name="Always delete", value=f"`{always_delete}`", inline=False)
        await ctx.send(embed=embed)