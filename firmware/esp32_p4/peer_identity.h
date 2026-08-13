// Test identities for peer protocol — pwnagotchi-style personas.
//
// Each persona has a name, title, ASCII face, and contextual quips
// that print during peer events (discovery, challenge, bonding, etc.).
// Select at compile time with PERSONA_ID (0-7), or at runtime via
// the "identity <n>" serial command.
//
// Default: auto-select from device_id hash.

#ifndef PEER_IDENTITY_H
#define PEER_IDENTITY_H

#define N_PERSONAS 8

struct Persona {
  const char *name;
  const char *title;
  const char *face_idle;
  const char *face_scanning;
  const char *face_found;
  const char *face_bonded;
  const char *face_rejected;
  const char *quip_boot;
  const char *quip_discover;
  const char *quip_challenge;
  const char *quip_verified;
  const char *quip_bonded;
  const char *quip_failed;
  const char *quip_timeout;
  const char *quip_lonely;
};

static const Persona PERSONAS[N_PERSONAS] = {
  {
    "GLITCH",
    "chaos gremlin",
    "(o_O)",
    "(o_o) ?",
    "(O_O) !",
    "(^_^)",
    "(>_<)",
    "woke up sideways. let's break things.",
    "fresh meat on the airwaves!",
    "prove you're not a toaster.",
    "ok you're legit. for now.",
    "ride or die. until I forget.",
    "nah, that ain't right.",
    "hello? anyone? ...rude.",
    "just me and the electrons."
  },
  {
    "SPECTRA",
    "signal ghost",
    "[-_-]",
    "[-_o]",
    "[o_o]",
    "[^_^]",
    "[x_x]",
    "listening on all frequencies.",
    "signal acquired. analyzing...",
    "transmitting challenge sequence.",
    "waveforms align. identity confirmed.",
    "frequencies locked. we resonate.",
    "harmonic mismatch. signal rejected.",
    "carrier lost. retransmitting...",
    "scanning the void."
  },
  {
    "BYTE",
    "friendly menace",
    ":3",
    ":3 ?",
    ":D !",
    "B)",
    "D:",
    "hewwo! i will eat your firmware.",
    "ooh! who are you!",
    "pop quiz, hotshot.",
    "you pass! ...this time.",
    "besties!! *nuzzles your antenna*",
    "imposter!! get away!!",
    "did you fall asleep?",
    "*sad beeping noises*"
  },
  {
    "WRAITH",
    "silent validator",
    "...",
    ". . .",
    "(!)",
    "(+)",
    "(x)",
    "online.",
    "contact.",
    "authenticate.",
    "confirmed.",
    "allied.",
    "rejected.",
    "no response.",
    "waiting."
  },
  {
    "AXIOM",
    "protocol purist",
    "{=_=}",
    "{=_o}",
    "{O_O}",
    "{^_^}",
    "{#_#}",
    "all systems nominal. running diagnostics.",
    "new node detected. initiating handshake.",
    "dispatching validation payload.",
    "cryptographic identity verified.",
    "peer relationship established. RFC compliant.",
    "verification failed. non-conforming peer.",
    "ACK timeout exceeded. retransmitting.",
    "no peers in range. standby mode."
  },
  {
    "JINX",
    "lucky charm",
    "~(^.^)~",
    "~(o.o)~",
    "~(O.O)~",
    "~(*.*) ~",
    "~(T.T)~",
    "feeling lucky! let's find friends!",
    "ooh, someone's out there!",
    "double or nothing — show me your tokens!",
    "jackpot! you're the real deal!",
    "we're on a roll! bonded!!",
    "bad beat... that wasn't right.",
    "come oooon... answer me!",
    "table for one, I guess."
  },
  {
    "KERN",
    "grizzled veteran",
    "-_-",
    "o_-",
    "o_o",
    "^_-",
    ">_-",
    "seen it all. let's get this over with.",
    "well, look who wandered in.",
    "alright kid, let's see what you got.",
    "not bad. you check out.",
    "fine. we ride together now.",
    "get out of here with that garbage.",
    "typical. nobody answers anymore.",
    "same old empty airwaves."
  },
  {
    "NEON",
    "hype machine",
    "\\(^o^)/",
    "\\(^.^)/",
    "\\(O_O)/",
    "\\(*_*)/",
    "\\(T_T)/",
    "LET'S GOOOOO!! WHO'S OUT THERE?!",
    "YOOOO NEW PEER DETECTED!!",
    "SHOW ME WHAT YOU GOT!!",
    "THEY'RE LEGIT!! TOKENS MATCH!!",
    "BONDED!! THIS IS AMAZING!!",
    "DENIED!! BETTER LUCK NEXT TIME!!",
    "HELLO?! IS THIS THING ON?!",
    "it's quiet... too quiet..."
  }
};

// State for runtime persona selection.
static int _persona_idx = -1;  // -1 = auto from device_id

static const Persona *_active_persona = NULL;

static void persona_select(int idx) {
  if (idx < 0 || idx >= N_PERSONAS) idx = 0;
  _persona_idx = idx;
  _active_persona = &PERSONAS[idx];
}

static void persona_auto(uint32_t device_id) {
  if (_persona_idx >= 0) return;  // manual override
  int idx = (int)((device_id >> 8) % N_PERSONAS);
  _persona_idx = idx;
  _active_persona = &PERSONAS[idx];
}

static const Persona *persona() {
  return _active_persona ? _active_persona : &PERSONAS[0];
}

static void persona_boot() {
  const Persona *p = persona();
  Serial.println();
  Serial.printf("  %s\n", p->face_idle);
  Serial.printf("  %s \"%s\"\n", p->name, p->title);
  Serial.printf("  %s\n\n", p->quip_boot);
}

static void persona_print_roster() {
  Serial.println("\n--- available identities ---");
  for (int i = 0; i < N_PERSONAS; i++) {
    const char *mark = (i == _persona_idx) ? " <--" : "";
    Serial.printf("  %d: %-8s %s  \"%s\"%s\n",
                  i, PERSONAS[i].name, PERSONAS[i].face_idle,
                  PERSONAS[i].title, mark);
  }
  Serial.println();
}

#endif
