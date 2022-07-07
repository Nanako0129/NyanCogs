from .phishingchecker import PhishingChecker

def setup(bot):
    bot.add_cog(PhishingChecker(bot))
    return bot