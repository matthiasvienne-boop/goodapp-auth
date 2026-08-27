import { timingSafeEqual } from "node:crypto";

/**
 * Vergelijkt twee geheimen in constante tijd.
 *
 * WAAROM DIT EEN EIGEN FUNCTIE IS
 *
 * De gewone vergelijking stopt bij het eerste verschillende teken. Het
 * tijdsverschil is klein, maar het is er en het schaalt met het aantal
 * pogingen. Bij BeleggersApp stond precies die fout in de tokencontrole van een
 * intern eindpunt (BEL-317, 27 augustus 2026), terwijl de oplossing elders in
 * het portfolio al bestond. Dat is de reden dat dit hier staat en niet vier
 * keer apart.
 *
 * timingSafeEqual werpt bij verschillende lengtes. Die lengte lekt sowieso al
 * — ze is af te leiden uit het antwoord — dus dat verschil wordt hier
 * afgevangen en niet verborgen: ongelijke lengte is gewoon niet gelijk.
 */
export function secretsMatch(aangeleverd: unknown, verwacht: string | undefined | null): boolean {
  if (typeof aangeleverd !== "string" || !aangeleverd) return false;
  if (!verwacht) return false;

  const a = Buffer.from(aangeleverd, "utf8");
  const b = Buffer.from(verwacht, "utf8");
  if (a.length !== b.length) return false;

  return timingSafeEqual(a, b);
}
