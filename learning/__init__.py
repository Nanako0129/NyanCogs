"""Learning Red cog package."""

import json
from pathlib import Path

from redbot.core.bot import Red

from .learning import Learning

with (Path(__file__).parent / "info.json").open(encoding="utf-8") as fp:
    __red_end_user_data_statement__ = json.load(fp)["end_user_data_statement"]


async def setup(bot: Red) -> None:
    """Load the Learning cog."""
    await bot.add_cog(Learning(bot))
