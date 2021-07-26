from .geysermc import Geysermc

def setup(bot):
    bot.add_cog(Geysermc(bot))