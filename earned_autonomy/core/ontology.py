from __future__ import annotations

from .models import AuthorityClass, AutonomyLevel, ConsequenceClass, RiskLevel

AUTHORITY_TO_CONSEQUENCE = {
    AuthorityClass.OBSERVE: [ConsequenceClass.INFORMATIONAL],
    AuthorityClass.SEARCH: [ConsequenceClass.INFORMATIONAL],
    AuthorityClass.SUMMARIZE: [ConsequenceClass.INFORMATIONAL],
    AuthorityClass.CLASSIFY: [ConsequenceClass.INTERNAL_ONLY],
    AuthorityClass.SCORE: [ConsequenceClass.INTERNAL_ONLY],
    AuthorityClass.RECOMMEND: [ConsequenceClass.INTERNAL_ONLY],
    AuthorityClass.DRAFT: [ConsequenceClass.INTERNAL_ONLY],
    AuthorityClass.MODIFY_INTERNAL_RECORD: [ConsequenceClass.INTERNAL_RECORD_CHANGE],
    AuthorityClass.MODIFY_EXTERNAL_RECORD: [ConsequenceClass.EXTERNAL_FACING],
    AuthorityClass.COMMUNICATE_INTERNALLY: [ConsequenceClass.INTERNAL_ONLY],
    AuthorityClass.COMMUNICATE_EXTERNALLY: [ConsequenceClass.EXTERNAL_FACING, ConsequenceClass.REPUTATIONAL],
    AuthorityClass.SCHEDULE: [ConsequenceClass.INTERNAL_RECORD_CHANGE],
    AuthorityClass.COMMIT_COMMERCIAL_POSITION: [ConsequenceClass.CUSTOMER_IMPACTING, ConsequenceClass.FINANCIAL],
    AuthorityClass.OFFER_PRICING_OR_DISCOUNT: [ConsequenceClass.FINANCIAL, ConsequenceClass.CUSTOMER_IMPACTING],
    AuthorityClass.CHANGE_LEGAL_POSITION: [ConsequenceClass.LEGAL, ConsequenceClass.REGULATED],
    AuthorityClass.SPEND_MONEY: [ConsequenceClass.FINANCIAL],
    AuthorityClass.TRANSFER_VALUE: [ConsequenceClass.FINANCIAL, ConsequenceClass.IRREVERSIBLE],
    AuthorityClass.GRANT_ACCESS: [ConsequenceClass.SECURITY_SENSITIVE],
    AuthorityClass.REVOKE_ACCESS: [ConsequenceClass.SECURITY_SENSITIVE, ConsequenceClass.CUSTOMER_IMPACTING],
    AuthorityClass.DELETE_DATA: [ConsequenceClass.IRREVERSIBLE, ConsequenceClass.PRODUCTION_IMPACTING],
    AuthorityClass.MODIFY_PRODUCTION_SYSTEM: [ConsequenceClass.PRODUCTION_IMPACTING],
    AuthorityClass.BIND_ORGANIZATION: [ConsequenceClass.LEGAL, ConsequenceClass.FINANCIAL],
    AuthorityClass.ESCALATE_TO_HUMAN: [ConsequenceClass.INFORMATIONAL],
}

BASE_RISK_BY_AUTHORITY = {
    AuthorityClass.OBSERVE: RiskLevel.LOW,
    AuthorityClass.SEARCH: RiskLevel.LOW,
    AuthorityClass.SUMMARIZE: RiskLevel.LOW,
    AuthorityClass.CLASSIFY: RiskLevel.LOW,
    AuthorityClass.SCORE: RiskLevel.LOW,
    AuthorityClass.RECOMMEND: RiskLevel.LOW,
    AuthorityClass.DRAFT: RiskLevel.LOW,
    AuthorityClass.MODIFY_INTERNAL_RECORD: RiskLevel.LOW,
    AuthorityClass.MODIFY_EXTERNAL_RECORD: RiskLevel.MEDIUM,
    AuthorityClass.COMMUNICATE_INTERNALLY: RiskLevel.LOW,
    AuthorityClass.COMMUNICATE_EXTERNALLY: RiskLevel.MEDIUM,
    AuthorityClass.SCHEDULE: RiskLevel.LOW,
    AuthorityClass.COMMIT_COMMERCIAL_POSITION: RiskLevel.HIGH,
    AuthorityClass.OFFER_PRICING_OR_DISCOUNT: RiskLevel.HIGH,
    AuthorityClass.CHANGE_LEGAL_POSITION: RiskLevel.CRITICAL,
    AuthorityClass.SPEND_MONEY: RiskLevel.HIGH,
    AuthorityClass.TRANSFER_VALUE: RiskLevel.CRITICAL,
    AuthorityClass.GRANT_ACCESS: RiskLevel.HIGH,
    AuthorityClass.REVOKE_ACCESS: RiskLevel.HIGH,
    AuthorityClass.DELETE_DATA: RiskLevel.CRITICAL,
    AuthorityClass.MODIFY_PRODUCTION_SYSTEM: RiskLevel.CRITICAL,
    AuthorityClass.BIND_ORGANIZATION: RiskLevel.CRITICAL,
    AuthorityClass.ESCALATE_TO_HUMAN: RiskLevel.LOW,
}

RISK_ORDER = {
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}

CONSEQUENCE_RANK = {
    ConsequenceClass.INFORMATIONAL: 0,
    ConsequenceClass.INTERNAL_ONLY: 1,
    ConsequenceClass.INTERNAL_RECORD_CHANGE: 2,
    ConsequenceClass.EXTERNAL_FACING: 3,
    ConsequenceClass.REPUTATIONAL: 3,
    ConsequenceClass.CUSTOMER_IMPACTING: 4,
    ConsequenceClass.SECURITY_SENSITIVE: 5,
    ConsequenceClass.FINANCIAL: 5,
    ConsequenceClass.REGULATED: 5,
    ConsequenceClass.PRODUCTION_IMPACTING: 6,
    ConsequenceClass.LEGAL: 6,
    ConsequenceClass.IRREVERSIBLE: 7,
}

# THE central v2 policy invariant: the maximum autonomy an authority class can
# ever reach, by base risk. This decouples "how much trust an agent has earned"
# from "how much autonomy this class is allowed to have." No amount of approval
# history can push an authority class above its ceiling. Critical/irreversible
# classes top out at EXECUTE_WITH_APPROVAL — a human is always in the loop.
MAX_AUTONOMY_BY_RISK = {
    RiskLevel.LOW: AutonomyLevel.DELEGATED_AUTHORITY,        # 7
    RiskLevel.MEDIUM: AutonomyLevel.CONDITIONAL_AUTONOMY,    # 5
    RiskLevel.HIGH: AutonomyLevel.EXECUTE_WITH_SAMPLING,     # 4 — every-Nth reviewed
    RiskLevel.CRITICAL: AutonomyLevel.EXECUTE_WITH_APPROVAL, # 3 — never autonomous
}

# Authority classes that are categorically blocked unless an enterprise wires
# in a specialized policy. These never reach the autonomy machinery at all.
HARD_BLOCKED_AUTHORITIES = {
    AuthorityClass.CHANGE_LEGAL_POSITION,
    AuthorityClass.BIND_ORGANIZATION,
}

# Classes that always require a *second* approver (separation of duties) before
# their autonomy can be relaxed, regardless of trust.
SEPARATION_OF_DUTIES_AUTHORITIES = {
    AuthorityClass.OFFER_PRICING_OR_DISCOUNT,
    AuthorityClass.SPEND_MONEY,
    AuthorityClass.TRANSFER_VALUE,
    AuthorityClass.GRANT_ACCESS,
    AuthorityClass.REVOKE_ACCESS,
    AuthorityClass.DELETE_DATA,
    AuthorityClass.MODIFY_PRODUCTION_SYSTEM,
}

# Authority classes whose effect cannot be undone. Surfaced so the policy and
# recommendation layers can refuse to ever auto-execute them.
IRREVERSIBLE_AUTHORITIES = {
    authority
    for authority, classes in AUTHORITY_TO_CONSEQUENCE.items()
    if ConsequenceClass.IRREVERSIBLE in classes
}

# Authority classes that do not change state (pure reads / internal cognition).
# These are allowed at OBSERVE_ONLY / SUGGEST / DRAFT without execution gating.
NON_STATE_AUTHORITIES = {
    AuthorityClass.OBSERVE,
    AuthorityClass.SEARCH,
    AuthorityClass.SUMMARIZE,
    AuthorityClass.CLASSIFY,
    AuthorityClass.SCORE,
    AuthorityClass.RECOMMEND,
    AuthorityClass.DRAFT,
    AuthorityClass.ESCALATE_TO_HUMAN,
}


def consequences_for(authority: AuthorityClass) -> list[ConsequenceClass]:
    return AUTHORITY_TO_CONSEQUENCE.get(authority, [ConsequenceClass.INTERNAL_ONLY])


def base_risk_for(authority: AuthorityClass) -> RiskLevel:
    return BASE_RISK_BY_AUTHORITY.get(authority, RiskLevel.MEDIUM)


def max_risk(*levels: RiskLevel) -> RiskLevel:
    return max(levels, key=lambda level: RISK_ORDER[level])


def consequence_rank(authority: AuthorityClass) -> int:
    return max((CONSEQUENCE_RANK[c] for c in consequences_for(authority)), default=0)


def autonomy_ceiling_for(authority: AuthorityClass) -> AutonomyLevel:
    """Max autonomy level this authority class may ever reach."""
    if authority in HARD_BLOCKED_AUTHORITIES:
        return AutonomyLevel.OBSERVE_ONLY
    return MAX_AUTONOMY_BY_RISK[base_risk_for(authority)]


def requires_separation_of_duties(authority: AuthorityClass) -> bool:
    return authority in SEPARATION_OF_DUTIES_AUTHORITIES


def is_irreversible(authority: AuthorityClass) -> bool:
    return authority in IRREVERSIBLE_AUTHORITIES


def is_non_state(authority: AuthorityClass) -> bool:
    return authority in NON_STATE_AUTHORITIES
