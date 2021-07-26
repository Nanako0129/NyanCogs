import discord
from discord import colour
from discord.colour import Color
from redbot.core import commands
from redbot.core import Config
import json
import requests
import datetime
utcnow = datetime.datetime.utcnow
intervals = (
    ('週', 604800),  # 60 * 60 * 24 * 7
    ('天', 86400),    # 60 * 60 * 24
    ('小時', 3600),    # 60 * 60
    ('分鐘', 60),
    ('秒', 1),
    )
def display_time(seconds, granularity=2):
    result = []

    for name, count in intervals:
        value = seconds // count
        if value:
            seconds -= value * count
            if value == 1:
                name = name.rstrip('s')
            result.append("{} {}".format(value, name))
    return ' '.join(result[:granularity])

class Geysermc(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
    
    @commands.group(aliases=["gsmc"])
    async def geysermc(self, ctx):
        """顯示當前 GlobalAPI Skin 隊列 (Show states about the current GlobalAPI skin queue)"""
        pass

    @geysermc.command(name="show") 
    async def show_stats(self, ctx):
        """顯示當前 GlobalAPI Skin 隊列"""
        rep = requests.get("https://api.geysermc.org/v1/stats")
        em = discord.Embed()
        em.set_footer(text="https://api.geysermc.org/v1/stats", icon_url="https://cdn.discordapp.com/avatars/739572267855511652/548eef27f654909fb56a54bbcdbdff10.png?size=4096")
        em.timestamp = utcnow()
        if (rep.status_code==200):
            em.color = 5025359
            em.add_field(name="預先上傳隊列",value=rep.json().get("pre_upload_queue").get("length"),inline=True)
            em.add_field(name="上傳隊列",value=rep.json().get("upload_queue").get("length"),inline=True)
            em.add_field(name="預計上傳時間",value=display_time(seconds=(int(rep.json().get("upload_queue").get("estimated_duration"))),granularity=4),inline=True)
            em.title = "當前 GlobalAPI Skin 隊列"
        else:
            em.color = 16711680
            em.title = "無法從 API 取得資料！"
        await ctx.send(embed=em)


    