#ifndef PRINTSTATE_H_
#define PRINTSTATE_H_

// Disable ASCON debug printing (safe for Arduino Serial.print)
#define ascon_print(text)             ((void)0)
#define ascon_printbytes(text, b, l)  ((void)0)
#define ascon_printword(text, w)      ((void)0)
#define ascon_printstate(text, s)     ((void)0)

#endif /* PRINTSTATE_H_ */
