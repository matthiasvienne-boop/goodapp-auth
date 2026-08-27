import { randomBytes, createHash } from "node:crypto";
import { secretsMatch } from "./vergelijk";

export interface Hersteltoken {
  /** Wat de gebruiker in zijn mail krijgt. Bewaar dit nooit. */
  token: string;
  /** Wat je opslaat. Uit deze waarde is het token niet terug te rekenen. */
  hash: string;
  /** Wanneer het verloopt, als ISO-tijdstempel. */
  verlooptOp: string;
}

export interface HersteltokenOpties {
  /** Geldigheidsduur in minuten. Standaard zestig. */
  geldigMinuten?: number;
  /** Aantal willekeurige bytes. Standaard tweeëndertig. */
  bytes?: number;
  /** Alleen voor tests: het huidige moment. */
  nu?: () => Date;
}

/**
 * Maakt een hersteltoken.
 *
 * WAAROM ER TWEE WAARDEN UITKOMEN
 *
 * Het token gaat naar de gebruiker, de hash gaat naar de database. Wie de
 * database leest kan daarmee geen wachtwoord herstellen — en dat is precies het
 * scenario waarvoor een hersteltoken gevaarlijk is, want het omzeilt het
 * wachtwoord volledig.
 *
 * Een gewone SHA-256 en geen bcrypt: dit is een willekeurige waarde van
 * tweeëndertig bytes en geen door mensen gekozen wachtwoord. Er valt niets aan
 * te raden, dus een trage hash koopt hier niets.
 */
export function maakHersteltoken(opties: HersteltokenOpties = {}): Hersteltoken {
  const bytes = opties.bytes ?? 32;
  const minuten = opties.geldigMinuten ?? 60;
  const nu = (opties.nu ?? (() => new Date()))();

  const token = randomBytes(bytes).toString("base64url");
  return {
    token,
    hash: hashHersteltoken(token),
    verlooptOp: new Date(nu.getTime() + minuten * 60_000).toISOString(),
  };
}

/** De opgeslagen vorm van een token. Deterministisch, zodat je erop kunt zoeken. */
export function hashHersteltoken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

/**
 * Is dit token geldig voor deze opgeslagen hash, op dit moment?
 *
 * Verlopen en niet-overeenkomend geven allebei false, en met opzet zonder
 * onderscheid in het antwoord: wie aan het proberen is, hoort niet te leren of
 * hij het juiste token had maar te laat was.
 */
export function hersteltokenGeldig(
  token: string,
  opgeslagenHash: string,
  verlooptOp: string | Date,
  nu: Date = new Date()
): boolean {
  if (!token || !opgeslagenHash) return false;

  const grens = verlooptOp instanceof Date ? verlooptOp : new Date(verlooptOp);
  if (Number.isNaN(grens.getTime()) || grens.getTime() <= nu.getTime()) return false;

  return secretsMatch(hashHersteltoken(token), opgeslagenHash);
}
