from ..core.warden.enums import Action, Condition, Event
from ..enums import Rank
from ..core.warden.validation import ALLOWED_ACTIONS, ALLOWED_CONDITIONS, CONDITIONS_VALIDATORS, ACTIONS_VALIDATORS
from ..core.warden.validation import CONDITIONS_ANY_CONTEXT, CONDITIONS_USER_CONTEXT, CONDITIONS_MESSAGE_CONTEXT
from ..core.warden.validation import ACTIONS_ANY_CONTEXT, ACTIONS_USER_CONTEXT, ACTIONS_MESSAGE_CONTEXT
from ..core.warden.rule import WardenRule
from ..exceptions import InvalidRule
from . import wd_sample_rules as rl
from datetime import datetime, timedelta
import pytest


class FakeGuildPerms:
    manage_guild = False

class FakeMe:
    guild_permissions = FakeGuildPerms

class FakeRole:
    def __init__(self, _id, name):
        self.id = _id
        self.name = name

class FakeGuild:
    id = 852499907842801727
    me = FakeMe
    text_channels = {}
    roles = {}

    def get_role(self, _id):
        for role in self.roles:
            if _id == role.id:
                return role

FAKE_GUILD = FakeGuild()

class FakeChannel:
    id = 852499907842801728
    name = "fake"
    guild = FAKE_GUILD
    category = None
    mention = "<@852499907842801728>"

FAKE_CHANNEL = FakeChannel()

class FakeUser:
    nick = None
    name = "Twentysix"
    id = 852499907842801726
    guild = FAKE_GUILD
    mention = "<@852499907842801726>"
    created_at = datetime.utcnow()
    joined_at = datetime.utcnow()
    avatar_url = "test.com"
    roles = {}

FAKE_USER = FakeUser()

class FakeMessage:
    id = 852499907842801729
    guild = FAKE_GUILD
    channel = FAKE_CHANNEL
    author = FAKE_USER
    content = clean_content = "increase"
    created_at = datetime.utcnow()
    jump_url = ""
    attachments = []
    raw_mentions = []
    mentions = []
    role_mentions = []

FAKE_MESSAGE = FakeMessage()

def test_check_validators_consistency():
    def x_contains_only_y(x, y):
        for element in x:
            if not isinstance(element, y):
                return False
        return True

    for condition in Condition:
        assert condition in CONDITIONS_VALIDATORS

    for action in Action:
        assert action in ACTIONS_VALIDATORS

    i = 0
    print("Checking if conditions are in one and only one context...")
    for condition in Condition:
        print(f"Checking {condition.value}...")
        if condition in CONDITIONS_ANY_CONTEXT:
            i += 1

        if condition in CONDITIONS_USER_CONTEXT:
            i += 1

        if condition in CONDITIONS_MESSAGE_CONTEXT:
            i += 1

        assert i == 1
        i = 0

    i = 0
    print("Checking if actions are in one and only one context...")
    for action in Action:
        print(f"Checking {action.value}...")
        if action in ACTIONS_ANY_CONTEXT:
            i += 1

        if action in ACTIONS_USER_CONTEXT:
            i += 1

        if action in ACTIONS_MESSAGE_CONTEXT:
            i += 1

        assert i == 1
        i = 0

    assert x_contains_only_y(CONDITIONS_ANY_CONTEXT, Condition)
    assert x_contains_only_y(CONDITIONS_USER_CONTEXT, Condition)
    assert x_contains_only_y(CONDITIONS_MESSAGE_CONTEXT, Condition)
    assert x_contains_only_y(ACTIONS_ANY_CONTEXT, Action)
    assert x_contains_only_y(ACTIONS_USER_CONTEXT, Action)
    assert x_contains_only_y(ACTIONS_MESSAGE_CONTEXT, Action)

@pytest.mark.asyncio
async def test_rule_parsing():
    with pytest.raises(InvalidRule, match=r".*rank.*"):
        await WardenRule().parse(rl.INVALID_RANK, cog=None)
    with pytest.raises(InvalidRule, match=r".*event.*"):
        await WardenRule().parse(rl.INVALID_EVENT, cog=None)
    with pytest.raises(InvalidRule, match=r".*number.*"):
        await WardenRule().parse(rl.INVALID_PRIORITY, cog=None)
    with pytest.raises(InvalidRule, match=r".*'run-every' parameter is mandatory.*"):
        await WardenRule().parse(rl.INVALID_PERIODIC_MISSING_RUN_EVERY, cog=None)
    with pytest.raises(InvalidRule, match=r".*'periodic' event must be specified.*"):
        await WardenRule().parse(rl.INVALID_PERIODIC_MISSING_EVENT, cog=None)
    with pytest.raises(InvalidRule, match=r".*Condition `message-matches-any` not allowed*"):
        await WardenRule().parse(rl.INVALID_MIXED_RULE_CONDITION, cog=None)
    with pytest.raises(InvalidRule, match=r".*Action `delete-user-message` not allowed*"):
        await WardenRule().parse(rl.INVALID_MIXED_RULE_ACTION, cog=None)

    await WardenRule().parse(rl.TUTORIAL_SIMPLE_RULE, cog=None)
    await WardenRule().parse(rl.TUTORIAL_PRIORITY_RULE, cog=None)
    await WardenRule().parse(rl.VALID_MIXED_RULE, cog=None)

    rule = WardenRule()
    await rule.parse(rl.TUTORIAL_COMPLEX_RULE, cog=None)
    assert isinstance(rule.rank, Rank)
    assert rule.name and isinstance(rule.name, str)
    assert rule.raw_rule and isinstance(rule.raw_rule, str)
    assert rule.events and isinstance(rule.events, list)
    assert rule.conditions and isinstance(rule.conditions, list)
    assert rule.actions and isinstance(rule.actions, list)

    # TODO Add rules to check for invalid types, non-empty lists, etc
    # Restore allowed events tests

@pytest.mark.asyncio
async def test_rule_cond_eval():
    rule = WardenRule()
    await rule.parse(rl.CONDITION_TEST_POSITIVE, cog=None)
    assert bool(await rule.satisfies_conditions(
        cog=None,
        rank=Rank.Rank1,
        guild=FAKE_GUILD,
        user=FAKE_USER)) is True

    rule = WardenRule()
    await rule.parse(rl.CONDITION_TEST_NEGATIVE, cog=None)
    assert bool(await rule.satisfies_conditions(
        cog=None,
        rank=Rank.Rank1,
        guild=FAKE_GUILD,
        user=FAKE_USER)) is False

    positive_comparisons = (
        '[1, "==", 1]',
        '[1, "!=", 2]',
        '[2, ">", 1]',
        '[1, "<", 2]',
        '[3, ">=", 3]',
        '[4, ">=", 3]',
        '[3, "<=", 3]',
        '[3, "<=", 5]',
        '[hello, contains, ll]',
        '[hello, contains-pattern, "H?ll*"]', # should NOT be case sensitive
    )

    negative_comparisons = (
        '[2, "==", 1]',
        '[1, "!=", 1]',
        '[2, ">", 4]',
        '[4, "<", 2]',
        '[3, ">=", 5]',
        '[5, "<=", 3]',
        '[hello, contains, xx]',
        '[hello, contains-pattern, "h?xx*"]',
    )

    expected_result = (True, False)
    for i, comparison_list in enumerate((positive_comparisons, negative_comparisons)):
        for comp in comparison_list:
            print(comp)
            rule = WardenRule()
            await rule.parse(rl.DYNAMIC_RULE.format(
                rank="1",
                event="on-user-join",
                conditions=f"    - compare: {comp}",
                actions="    - no-op:"
                ), cog=None)
            assert bool(await rule.satisfies_conditions(
                cog=None,
                rank=Rank.Rank1,
                guild=FAKE_GUILD,
                user=FAKE_USER)) is expected_result[i]

    ##### Sandbox store
    rule = WardenRule()
    await rule.parse(rl.CHECK_HEATPOINTS, cog=None)
    assert bool(await rule.satisfies_conditions(
        cog=None,
        rank=Rank.Rank1,
        guild=FAKE_GUILD,
        message=FAKE_MESSAGE)) is False

    rule = WardenRule()
    await rule.parse(rl.INCREASE_HEATPOINTS, cog=None)
    assert bool(await rule.satisfies_conditions(
        cog=None,
        rank=Rank.Rank1,
        guild=FAKE_GUILD,
        message=FAKE_MESSAGE)) is True
    await rule.do_actions(cog=None,
        guild=FAKE_GUILD,
        message=FAKE_MESSAGE)

    rule = WardenRule()
    await rule.parse(rl.CHECK_HEATPOINTS, cog=None)
    assert bool(await rule.satisfies_conditions(
        cog=None,
        rank=Rank.Rank1,
        guild=FAKE_GUILD,
        message=FAKE_MESSAGE)) is True
    ##############

    ##### Prod store
    rule = WardenRule()
    await rule.parse(rl.CHECK_HEATPOINTS, cog=None)
    assert bool(await rule.satisfies_conditions(
        cog=None,
        rank=Rank.Rank1,
        guild=FAKE_GUILD,
        message=FAKE_MESSAGE,
        debug=True)) is False

    rule = WardenRule()
    await rule.parse(rl.INCREASE_HEATPOINTS, cog=None)
    assert bool(await rule.satisfies_conditions(
        cog=None,
        rank=Rank.Rank1,
        guild=FAKE_GUILD,
        message=FAKE_MESSAGE,
        debug=True)) is True
    await rule.do_actions(cog=None,
        guild=FAKE_GUILD,
        message=FAKE_MESSAGE,
        debug=True)

    rule = WardenRule()
    await rule.parse(rl.CHECK_HEATPOINTS, cog=None)
    assert bool(await rule.satisfies_conditions(
        cog=None,
        rank=Rank.Rank1,
        guild=FAKE_GUILD,
        message=FAKE_MESSAGE,
        debug=True)) is True
    ##############

    rule = WardenRule()
    await rule.parse(rl.EMPTY_HEATPOINTS, cog=None)
    assert bool(await rule.satisfies_conditions(
        cog=None,
        rank=Rank.Rank1,
        guild=FAKE_GUILD,
        message=FAKE_MESSAGE,
        debug=True)) is True
    await rule.do_actions(cog=None,
        guild=FAKE_GUILD,
        message=FAKE_MESSAGE,
        debug=True)

    rule = WardenRule()
    await rule.parse(rl.CHECK_EMPTY_HEATPOINTS, cog=None)
    assert bool(await rule.satisfies_conditions(
        cog=None,
        rank=Rank.Rank1,
        guild=FAKE_GUILD,
        message=FAKE_MESSAGE,
        debug=True)) is True


    rule = WardenRule()
    await rule.parse(rl.CHECK_EMPTY_HEATPOINTS, cog=None)
    assert bool(await rule.satisfies_conditions(
        cog=None,
        rank=Rank.Rank1,
        guild=FAKE_GUILD,
        message=FAKE_MESSAGE)) is False

    rule = WardenRule()
    await rule.parse(rl.EMPTY_HEATPOINTS, cog=None)
    assert bool(await rule.satisfies_conditions(
        cog=None,
        rank=Rank.Rank1,
        guild=FAKE_GUILD,
        message=FAKE_MESSAGE)) is True
    await rule.do_actions(cog=None,
        guild=FAKE_GUILD,
        message=FAKE_MESSAGE)

    rule = WardenRule()
    await rule.parse(rl.CHECK_EMPTY_HEATPOINTS, cog=None)
    assert bool(await rule.satisfies_conditions(
        cog=None,
        rank=Rank.Rank1,
        guild=FAKE_GUILD,
        message=FAKE_MESSAGE)) is True

    rule = WardenRule()
    await rule.parse(rl.CONDITIONAL_ACTION_TEST_ASSIGN, cog=None)
    await rule.do_actions(cog=None,
        guild=FAKE_GUILD,
        message=FAKE_MESSAGE)

    rule = WardenRule()
    await rule.parse(rl.CONDITIONAL_ACTION_TEST_CHECK, cog=None)
    assert bool(await rule.satisfies_conditions(
        cog=None,
        rank=Rank.Rank1,
        guild=FAKE_GUILD,
        message=FAKE_MESSAGE)) is True

@pytest.mark.asyncio
async def test_conditions():
    async def eval_cond(condition: Condition, params, expected_result: bool):
        rule = WardenRule()
        await rule.parse(
            rl.CONDITION_TEST.format(
                condition.value,
                params,
            ),
            cog=None
        )

        assert bool(await rule.satisfies_conditions(
            cog=None,
            rank=Rank.Rank1,
            guild=FAKE_GUILD,
            message=FAKE_MESSAGE)) is expected_result

    FAKE_MESSAGE.content = "aaa 2626 aaa"
    await eval_cond(Condition.MessageMatchesAny, ["abcd", "*hello*"], False)
    await eval_cond(Condition.MessageMatchesAny, ["*2626*", "hi", 12345], True)

    FAKE_MESSAGE.attachments = []
    await eval_cond(Condition.MessageHasAttachment, "true", False)
    await eval_cond(Condition.MessageHasAttachment, "false", True)
    FAKE_MESSAGE.attachments = ["aaa"]
    await eval_cond(Condition.MessageHasAttachment, "true", True)
    await eval_cond(Condition.MessageHasAttachment, "false", False)

    FAKE_MESSAGE.content = "aaa 2626 aaa"
    await eval_cond(Condition.MessageContainsUrl, "true", False)
    await eval_cond(Condition.MessageContainsUrl, "false", True)
    FAKE_MESSAGE.content = "aaa https://discord.red aaa"
    await eval_cond(Condition.MessageContainsUrl, "true", True)
    await eval_cond(Condition.MessageContainsUrl, "false", False)

    FAKE_MESSAGE.content = "aaa 2626 aaa"
    await eval_cond(Condition.MessageContainsInvite, "true", False)
    await eval_cond(Condition.MessageContainsInvite, "false", True)
    FAKE_MESSAGE.content = "aaa https://discord.gg/red aaa"
    await eval_cond(Condition.MessageContainsInvite, "true", True)
    await eval_cond(Condition.MessageContainsInvite, "false", False)

    FAKE_MESSAGE.content = "aaa 2626 https://discord.gg/file.txt aaa"
    await eval_cond(Condition.MessageContainsMedia, "true", False)
    await eval_cond(Condition.MessageContainsMedia, "false", True)
    FAKE_MESSAGE.content = "aaa https://discord.gg/file.jpg aaa"
    await eval_cond(Condition.MessageContainsMedia, "true", True)
    await eval_cond(Condition.MessageContainsMedia, "false", False)

    FAKE_MESSAGE.raw_mentions = ["<@26262626262626>"]
    await eval_cond(Condition.MessageContainsMTMentions, 1, False)
    FAKE_MESSAGE.raw_mentions = ["<@26262626262626>", "<@26262626262626>"]
    await eval_cond(Condition.MessageContainsMTMentions, 1, True)

    FAKE_MESSAGE.mentions = ["<@26262626262626>", "<@26262626262626>"]
    await eval_cond(Condition.MessageContainsMTUniqueMentions, 1, False)
    FAKE_MESSAGE.mentions = ["<@26262626262626>", "<@123456789033221>"]
    await eval_cond(Condition.MessageContainsMTUniqueMentions, 1, True)

    FAKE_MESSAGE.role_mentions = ["<@26262626262626>"]
    await eval_cond(Condition.MessageContainsMTRolePings, 1, False)
    FAKE_MESSAGE.role_mentions = ["<@26262626262626>", "<@26262626262626>"]
    await eval_cond(Condition.MessageContainsMTRolePings, 1, True)

    FAKE_MESSAGE.clean_content = "2626"
    await eval_cond(Condition.MessageHasMTCharacters, 3, True)
    await eval_cond(Condition.MessageHasMTCharacters, 4, False)

    FAKE_USER.id = 262626
    await eval_cond(Condition.UserIdMatchesAny, [123456, "123424234"], False)
    await eval_cond(Condition.UserIdMatchesAny, [12, "262626"], True)

    FAKE_USER.name = "Twentysix"
    await eval_cond(Condition.UsernameMatchesAny, ["dsaasdasd", "Twentysix"], True)
    await eval_cond(Condition.UsernameMatchesAny, ["dsaasd", "dsadss"], False)

    FAKE_USER.nick = None
    await eval_cond(Condition.NicknameMatchesAny, ["dsaasdasd", "Twentysix"], False)
    FAKE_USER.nick = "Twentysix"
    await eval_cond(Condition.NicknameMatchesAny, ["dsaasdasd", "Twentysix"], True)
    await eval_cond(Condition.NicknameMatchesAny, ["dsaasd", "dsadss"], False)

    FAKE_USER.joined_at = datetime.utcnow()
    await eval_cond(Condition.UserJoinedLessThan, 1, True)
    FAKE_USER.joined_at = datetime.utcnow() - timedelta(hours=2)
    await eval_cond(Condition.UserJoinedLessThan, 1, False)

    FAKE_USER.created_at = datetime.utcnow()
    await eval_cond(Condition.UserCreatedLessThan, 1, True)
    FAKE_USER.created_at = datetime.utcnow() - timedelta(hours=2)
    await eval_cond(Condition.UserCreatedLessThan, 1, False)

    FAKE_USER.avatar_url = "discord.gg/ad/sda/s/ads.png"
    await eval_cond(Condition.UserHasDefaultAvatar, "true", False)
    await eval_cond(Condition.UserHasDefaultAvatar, "false", True)
    FAKE_USER.avatar_url = "discord.gg/asddasad/embed/avatars/2.png"
    await eval_cond(Condition.UserHasDefaultAvatar, "true", True)
    await eval_cond(Condition.UserHasDefaultAvatar, "false", False)

    FAKE_CHANNEL.id = 262626
    FAKE_CHANNEL.name = "my-ch"
    FAKE_GUILD.text_channels[FAKE_CHANNEL] = FAKE_CHANNEL
    await eval_cond(Condition.ChannelMatchesAny, [12345, "asdas"], False)
    await eval_cond(Condition.ChannelMatchesAny, [12345, "262626"], True)
    await eval_cond(Condition.ChannelMatchesAny, ["my-ch", "1111111"], True)

    role1 = FakeRole(12345, "my_role")
    role2 = FakeRole(67890, "my_role2")
    FAKE_GUILD.roles[role1] = role1
    FAKE_GUILD.roles[role2] = role2
    await eval_cond(Condition.UserHasAnyRoleIn, [12345, "1111111"], False)
    await eval_cond(Condition.UserHasAnyRoleIn, ["dassdads", "my_role"], False)
    FAKE_USER.roles[role1] = role1
    await eval_cond(Condition.UserHasAnyRoleIn, [12345, "1111111"], True)
    await eval_cond(Condition.UserHasAnyRoleIn, ["dassdads", "my_role"], True)

    # Missing tests for category, public channels, regex related and emojis