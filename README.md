# @goodapp/auth

Het deel van authenticatie dat **geen database raakt**: wachtwoorden hashen, JWT's
tekenen en verifiëren, hersteltokens maken en controleren, en geheimen
vergelijken in constante tijd.

Vierde gedeelde pakket, na
[`@goodapp/observability`](https://github.com/matthiasvienne-boop/goodapp-observability)
en [`@goodapp/email`](https://github.com/matthiasvienne-boop/goodapp-email).

## Waarom dit bestaat

Vier producten hebben een eigen login: BeleggersApp, Brickstory, Veynoris en
TijdReg. Op 27 augustus 2026 is gemeten wat ze werkelijk doen, en niet wat ze
lijken te doen:

- alle vier gebruiken `bcryptjs@^2.4.3` en `jsonwebtoken@^9.0.2` — dezelfde
  bibliotheken, dezelfde versies;
- de kostenfactor loopt uiteen: twaalf bij drie producten, tien bij
  BeleggersApp;
- en Veynoris is intern niet consistent — `auth.ts` hasht met twaalf,
  `reports.ts` met tien voor het wachtwoord van een gedeeld rapport.

Dat laatste is het punt. Niemand heeft die tien gekozen en niemand zag hem. Vier
keer hetzelfde bouwen betekent vier keer eigen fouten, en die kosten zijn niet
theoretisch: PLAT-61 was één fout in de foutregistratie die twee producten
tegelijk trof, BEL-317 een tokencontrole die niet in constante tijd vergeleek
terwijl de oplossing elders al bestond.

## Waarom niet méér dan dit

Er zijn drie databaselagen in gebruik — Prisma, Drizzle en rauwe `pg`. Alles wat
de database raakt valt daarmee niet te delen. Dat is geen reden om af te zien,
wel om te splitsen:

| Deel | Raakt de database | Hier |
|---|---|---|
| Wachtwoorden hashen en verifiëren | nee | ja |
| JWT tekenen, verifiëren, verlopen | nee | ja |
| Hersteltoken maken en controleren | nee | ja |
| Vergelijken in constante tijd | nee | ja |
| De gebruiker opzoeken en opslaan | ja | nee |
| Sessies bijhouden | ja | nee |

De bovenste vier zijn samen het grootste deel van wat er fout kan gaan, en juist
die raken de database niet.

**Dit mag geen framework worden.** Een gedeeld pakket dat alles kan, zet elk
product vast aan de kleinste gemene deler. De maatstaf blijft: deel wat
aantoonbaar identiek is, niet wat er hetzelfde uitziet. Bij dezelfde doorlichting
bleek `env-validation.ts` er in drie producten hetzelfde uit te zien en het niet
te zijn — dat waren drie configuraties bovenop één gedeeld mechanisme.

## Gebruik

```ts
import {
  hashPassword, verifyPassword, moetOpnieuwGehashtWorden,
  signToken, verifyToken,
  maakHersteltoken, hersteltokenGeldig,
  secretsMatch,
} from "@goodapp/auth";

const hash = await hashPassword(wachtwoord);            // standaard twaalf ronden
if (!(await verifyPassword(ingevoerd, hash))) return 401;

// Geldigheidsduur is verplicht en heeft geen standaardwaarde: hoe lang een
// gestolen token bruikbaar blijft is een keuze, en die hoort zichtbaar te zijn.
const token = signToken({ sub: id }, geheim, { geldigheidsduur: "1h" });

const r = verifyToken(token, geheim);
if (!r.geldig && r.reden === "verlopen") return 401;    // anders dan "ongeldig"
```

### Twee dingen die geen optie zijn

**Het algoritme.** `signToken` gebruikt HS256 en laat de aanroeper niet kiezen.
Wie het algoritme mag kiezen kan `none` kiezen, en dan wordt een token zonder
handtekening aanvaard. Vastzetten kost niets en sluit die hele categorie uit.

**De uitkomst van `verifyToken`.** Verlopen en ongeldig komen apart terug, want
de aanroeper hoort ze verschillend te behandelen. Welke controle precies faalde
komt níet naar buiten: een verkeerde handtekening en een verkeerde uitgever
lezen hetzelfde.

## Tests

```
npm test
```

Vijfentwintig tests, en die staan er vanaf de eerste commit. De twee eerdere
gedeelde pakketten begonnen zonder: bij `goodapp-observability` moesten er
achteraf vierentwintig bij toen er een echt lek in bleek te zitten (PLAT-61).
Dat is geen fout die je twee keer maakt.
