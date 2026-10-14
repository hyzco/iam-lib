/**
 * Role name normalisation for the authorization guards.
 *
 * The same tier is often spelled several ways (`super_admin`, `super-admin`,
 * `superadmin`). A role spelled one way in storage and compared another way
 * fails every ladder lookup, so each role is normalised here before it takes
 * part in an authorization decision.
 */

const ROLE_ALIASES = {
  "super-admin": "super_admin",
  superadmin: "super_admin",
  "admin-super": "super_admin",
};

/**
 * Canonicalise a role name. Returns null for empty/absent input so callers can
 * distinguish "no role" from a valid role.
 *
 * @param {unknown} role
 * @returns {string|null}
 */
export function normalizeRole(role) {
  const normalized = String(role ?? "").trim().toLowerCase();
  if (!normalized) {
    return null;
  }

  return ROLE_ALIASES[normalized] ?? normalized;
}

/**
 * Pick the higher-ranked of two roles against an ordered ladder (lowest rank first).
 * Unknown roles rank below every known role. Returns null when neither is known.
 *
 * @param {string[]} ladder
 * @param {...unknown} candidates
 * @returns {string|null}
 */
export function highestRole(ladder, ...candidates) {
  let best = null;
  let bestIndex = -1;

  for (const candidate of candidates) {
    const normalized = normalizeRole(candidate);
    if (!normalized) {
      continue;
    }

    const index = ladder.indexOf(normalized);
    if (index > bestIndex) {
      bestIndex = index;
      best = normalized;
    } else if (best === null) {
      // Keep an unknown role rather than returning null: the guards fail closed on
      // unknown roles anyway, and preserving it keeps the denial log meaningful.
      best = normalized;
    }
  }

  return best;
}

export default { normalizeRole, highestRole };
