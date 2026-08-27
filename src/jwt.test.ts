import test from "node:test";
import assert from "node:assert/strict";
import jwt from "jsonwebtoken";
import { signToken, verifyToken } from "./jwt";

const GEHEIM = "test-geheim-dat-lang-genoeg-is";

test("signToken en verifyToken: wat erin gaat komt eruit", () => {
  const t = signToken({ sub: "gebruiker-1", rol: "beheerder" }, GEHEIM, { geldigheidsduur: "1h" });
  const r = verifyToken<{ sub: string; rol: string }>(t, GEHEIM);
  assert.equal(r.geldig, true);
  if (r.geldig) {
    assert.equal(r.inhoud.sub, "gebruiker-1");
    assert.equal(r.inhoud.rol, "beheerder");
  }
});

test("verifyToken: een ander geheim maakt het token ongeldig", () => {
  const t = signToken({ sub: "1" }, GEHEIM, { geldigheidsduur: "1h" });
  const r = verifyToken(t, "een-ander-geheim");
  assert.deepEqual(r, { geldig: false, reden: "ongeldig" });
});

test("verifyToken: verlopen leest anders dan ongeldig", () => {
  // De aanroeper moet die twee kunnen scheiden: bij verlopen hoort de gebruiker
  // opnieuw aan te melden, bij ongeldig is er iets mis.
  const t = signToken({ sub: "1" }, GEHEIM, { geldigheidsduur: "-1s" });
  const r = verifyToken(t, GEHEIM);
  assert.deepEqual(r, { geldig: false, reden: "verlopen" });
});

test("verifyToken: een token zonder handtekening wordt niet aanvaard", () => {
  // De klassieke JWT-fout. Het algoritme staat vast op HS256 en is geen optie,
  // juist zodat dit niet kan.
  const zonder = jwt.sign({ sub: "1" }, "", { algorithm: "none" });
  const r = verifyToken(zonder, GEHEIM);
  assert.equal(r.geldig, false);
});

test("verifyToken: rommel is ongeldig en werpt niet", () => {
  for (const rommel of ["", "abc", "a.b.c", "..."]) {
    const r = verifyToken(rommel, GEHEIM);
    assert.equal(r.geldig, false, `token: ${rommel}`);
  }
});

test("verifyToken: een verkeerde uitgever leest als ongeldig, niet als iets anders", () => {
  // Welke controle faalde hoort niet naar buiten te komen: een verkeerde
  // handtekening en een verkeerde uitgever lezen hetzelfde.
  const t = signToken({ sub: "1" }, GEHEIM, { geldigheidsduur: "1h", uitgever: "veynoris" });
  const r = verifyToken(t, GEHEIM, { uitgever: "beleggersapp" });
  assert.deepEqual(r, { geldig: false, reden: "ongeldig" });
});

test("signToken: zonder geheim wordt er niets getekend", () => {
  assert.throws(() => signToken({ sub: "1" }, "", { geldigheidsduur: "1h" }), /geen geheim/);
});

test("speling vangt een klein klokverschil op", () => {
  const t = signToken({ sub: "1" }, GEHEIM, { geldigheidsduur: "-2s" });
  assert.equal(verifyToken(t, GEHEIM).geldig, false);
  assert.equal(verifyToken(t, GEHEIM, { speling: 30 }).geldig, true);
});
