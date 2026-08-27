import jwt from "jsonwebtoken";

export interface TekenOpties {
  /**
   * Hoe lang het token geldig is, in de vorm die jsonwebtoken kent ("1h", "7d").
   *
   * Bewust verplicht en zonder standaardwaarde. Gemeten op 27 augustus 2026
   * loopt dit per product uiteen: BeleggersApp gebruikt een uur voor toegang en
   * dertig dagen voor verversing, Veynoris een uur, Brickstory dertig dagen,
   * TijdReg zeven dagen. Dat zijn geen fouten maar keuzes over hoe lang een
   * gestolen token bruikbaar blijft, en die keuze hoort zichtbaar te zijn op de
   * plek waar hij gemaakt wordt — niet weggestopt in een standaardwaarde van
   * een gedeeld pakket.
   */
  geldigheidsduur: string | number;
  /** Wie het token uitgeeft. Optioneel, maar aanbevolen zodra er meer dan één uitgever is. */
  uitgever?: string;
  /** Voor wie het bedoeld is. */
  doelgroep?: string;
}

export interface VerifieerOpties {
  uitgever?: string;
  doelgroep?: string;
  /** Speelruimte in seconden voor klokverschil. Standaard nul. */
  speling?: number;
}

export type VerificatieUitkomst<T> =
  | { geldig: true; inhoud: T }
  | { geldig: false; reden: "verlopen" | "ongeldig" };

/**
 * Tekent een token met HS256.
 *
 * Het algoritme staat vast en is geen optie. Een aanroeper die het algoritme
 * mag kiezen, kan "none" kiezen — de klassieke JWT-fout, waarbij een token
 * zonder handtekening wordt aanvaard. Vastzetten kost niets en sluit die hele
 * categorie uit.
 */
export function signToken(
  inhoud: Record<string, unknown>,
  geheim: string,
  opties: TekenOpties
): string {
  if (!geheim) throw new Error("signToken: geen geheim");
  return jwt.sign(inhoud, geheim, {
    algorithm: "HS256",
    expiresIn: opties.geldigheidsduur as jwt.SignOptions["expiresIn"],
    ...(opties.uitgever ? { issuer: opties.uitgever } : {}),
    ...(opties.doelgroep ? { audience: opties.doelgroep } : {}),
  });
}

/**
 * Verifieert een token.
 *
 * Werpt nooit, en geeft het onderscheid terug dat de aanroeper nodig heeft:
 * verlopen is iets anders dan ongeldig. Bij het eerste hoort de gebruiker
 * opnieuw aan te melden, bij het tweede is er iets mis. Wie alleen true of
 * false teruggeeft, dwingt de aanroeper om die twee hetzelfde te behandelen.
 *
 * Wat er niet naar buiten komt is wélke controle faalde bij "ongeldig" — een
 * verkeerde handtekening en een verkeerde uitgever lezen hetzelfde.
 */
export function verifyToken<T = Record<string, unknown>>(
  token: string,
  geheim: string,
  opties: VerifieerOpties = {}
): VerificatieUitkomst<T> {
  if (!token || !geheim) return { geldig: false, reden: "ongeldig" };
  try {
    const inhoud = jwt.verify(token, geheim, {
      algorithms: ["HS256"],
      clockTolerance: opties.speling ?? 0,
      ...(opties.uitgever ? { issuer: opties.uitgever } : {}),
      ...(opties.doelgroep ? { audience: opties.doelgroep } : {}),
    }) as T;
    return { geldig: true, inhoud };
  } catch (err) {
    if (err instanceof jwt.TokenExpiredError) return { geldig: false, reden: "verlopen" };
    return { geldig: false, reden: "ongeldig" };
  }
}
