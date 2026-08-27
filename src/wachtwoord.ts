import bcrypt from "bcryptjs";

/**
 * De kostenfactor waarmee gehasht wordt wanneer een aanroeper er geen kiest.
 *
 * WAAROM TWAALF
 *
 * Gemeten op 27 augustus 2026 over de vier producten met een eigen login:
 * Brickstory, TijdReg en Veynoris hashen met twaalf, BeleggersApp met tien.
 * Twaalf is dus wat er feitelijk staat, en het is ook wat vandaag als redelijk
 * geldt — elke stap verdubbelt het rekenwerk voor wie een gestolen hash wil
 * kraken.
 *
 * Bij dezelfde meting bleek Veynoris intern niet consistent: auth.ts hasht met
 * twaalf, maar reports.ts hasht het wachtwoord van een gedeeld rapport met
 * tien. Dat is precies het soort verschil dat niemand kiest en niemand ziet,
 * en de reden dat dit getal op één plaats hoort te staan.
 */
export const STANDAARD_RONDEN = 12;

export interface HashOpties {
  /** Overschrijft STANDAARD_RONDEN. Alleen zetten met een reden die je kunt opschrijven. */
  ronden?: number;
}

/** Hasht een wachtwoord. Werpt bij een leeg wachtwoord: dat is nooit een geldige invoer. */
export async function hashPassword(wachtwoord: string, opties: HashOpties = {}): Promise<string> {
  if (!wachtwoord) {
    throw new Error("hashPassword: leeg wachtwoord");
  }
  const ronden = opties.ronden ?? STANDAARD_RONDEN;
  if (!Number.isInteger(ronden) || ronden < 4 || ronden > 20) {
    throw new Error(`hashPassword: ronden buiten bereik (${ronden}); verwacht 4 tot en met 20`);
  }
  return bcrypt.hash(wachtwoord, ronden);
}

/**
 * Controleert een wachtwoord tegen een hash.
 *
 * Werpt nooit. Een kapotte of lege hash levert false op en geen uitzondering:
 * een fout in de opslag mag geen aanmelding laten slagen, en mag ook niet als
 * een serverfout naar buiten komen — dat verschil is zelf informatie voor wie
 * aan het proberen is.
 */
export async function verifyPassword(wachtwoord: string, hash: string): Promise<boolean> {
  if (!wachtwoord || !hash) return false;
  try {
    return await bcrypt.compare(wachtwoord, hash);
  } catch {
    return false;
  }
}

/**
 * Is deze hash met een lagere kostenfactor gemaakt dan we nu willen?
 *
 * Bedoeld voor de plek waar iemand zich net geldig heeft aangemeld: dan heb je
 * het wachtwoord in handen en kun je opnieuw hashen zonder de gebruiker iets te
 * vragen. Zonder zoiets blijft een oude kostenfactor eeuwig staan.
 */
export function moetOpnieuwGehashtWorden(hash: string, opties: HashOpties = {}): boolean {
  const gewenst = opties.ronden ?? STANDAARD_RONDEN;
  const m = /^\$2[aby]\$(\d{2})\$/.exec(hash);
  if (!m) return false; // onbekende vorm: niets beweren
  return Number(m[1]) < gewenst;
}
