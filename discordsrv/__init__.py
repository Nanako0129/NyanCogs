from .discordsrv import DiscordSRV

def setup(bot):
    bot.add_cog(DiscordSRV(bot))