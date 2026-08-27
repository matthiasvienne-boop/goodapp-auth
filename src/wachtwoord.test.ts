import test from "node:test";
import assert from "node:assert/strict";
import { hashPassword, verifyPassword, moetOpnieuwGehashtWorden, STANDAARD_RONDEN } from "./wachtwoord";

test("hashPassword: een hash is niet het wachtwoord, en twee hashes zijn niet gelijk", async () => {
  const a = await hashPassword("geheim-123", { ronden: 4 });
  const b = await hashPassword("geheim-123", { ronden: 4 });
  assert.notEqual(a, "geheim-123");
  assert.notEqual(a, b, "bcrypt zout elke hash apart; gelijke hashes zouden dat weerleggen");
});

test("verifyPassword: het juiste wachtwoord slaagt, het verkeerde niet", async () => {
  const h = await hashPassword("geheim-123", { ronden: 4 });
  assert.equal(await verifyPassword("geheim-123", h), true);
  assert.equal(await verifyPassword("geheim-124", h), false);
});

test("verifyPassword: een kapotte hash levert false op en geen uitzondering", async () => {
  // Een fout in de opslag mag geen aanmelding laten slagen, en mag ook niet als
  // serverfout naar buiten komen — dat verschil is zelf informatie.
  for (const rommel of ["", "geen-hash", "$2a$kapot", "null"]) {
    assert.equal(await verifyPassword("geheim-123", rommel), false, `hash: ${rommel}`);
  }
});

test("verifyPassword: een leeg wachtwoord slaagt nooit", async () => {
  const h = await hashPassword("geheim-123", { ronden: 4 });
  assert.equal(await verifyPassword("", h), false);
});

test("hashPassword: een leeg wachtwoord is geen geldige invoer", async () => {
  await assert.rejects(() => hashPassword(""), /leeg wachtwoord/);
});

test("hashPassword: ronden buiten bereik worden geweigerd in plaats van stil aanvaard", async () => {
  await assert.rejects(() => hashPassword("x", { ronden: 2 }), /buiten bereik/);
  await assert.rejects(() => hashPassword("x", { ronden: 31 }), /buiten bereik/);
  await assert.rejects(() => hashPassword("x", { ronden: 10.5 }), /buiten bereik/);
});

test("de standaardkostenfactor is twaalf", () => {
  // Drie van de vier producten gebruiken twaalf; BeleggersApp is met tien de
  // uitzondering. Dit getal verlagen is een beslissing, geen detail.
  assert.equal(STANDAARD_RONDEN, 12);
});

test("moetOpnieuwGehashtWorden: een oudere kostenfactor wordt herkend", async () => {
  const oud = await hashPassword("geheim-123", { ronden: 4 });
  assert.equal(moetOpnieuwGehashtWorden(oud), true, "vier is lager dan twaalf");
  assert.equal(moetOpnieuwGehashtWorden(oud, { ronden: 4 }), false, "gelijk is niet lager");
});

test("moetOpnieuwGehashtWorden: over een onbekende vorm wordt niets beweerd", () => {
  assert.equal(moetOpnieuwGehashtWorden("geen-bcrypt-hash"), false);
});
