# si
Compilare:
    gcc server.c -o server.out -lssl -lcrypto
    gcc client.c -o client1.out -lssl -lcrypto
    gcc client.c -o client2.out -lssl -lcrypto

Rulare:

    - 3 terminale
        => ./server.out
        => ./client1.out
        => ./client2.out

Descriere:

    - server concurent, un proces pentru fiecare client
    - primul client conectat va primi rolul A si va trebui sa aleaga metoda de criptare (CBC/CFB),
      alegerea poate fi facuta inainte de conectarea clientului 2 (serverul va astepta ca ambii 
      clienti sa fie conectati inainte sa trimita raspunsurile) ==> recomandat (daca conectez ambii 
      clienti si dupa aleg metoda de criptare => crapa :) )
    - dupa ce ambii clienti sunt conectati si clientul A si-a ales metoda de criptare, serverul va 
      confirma metoda pentru fiecare client ( CBC pentru A => CFB pentru B si invers)
    - serverul va cripta K1, IV1, K2, IV2 folosind K3, IV3 si AES-128-CBC (openssl) prezente atat la clientul A cat si la clientul B
      si le va trimite sub forma de doua mesaje la fiecare din clienti.
    - clientii vor decripta mesajele (pentru K si pentru IV) folosind AES-128-CBC (openssl)
    - clientul B asteapta
    - clientul A citeste datele din fisier, le cripteaza folosind K si IV (CBC/CFB - implementare)
      si va trimite serverului numarul de blocuri, lungimea unui bloc respectiv si cate un bloc de cryptotext 
      (pentru fiecare bloc in parte);
    - serverul primeste, concateneaza blocurile de text si le decripteaza folosind K1, IV1 (CBC/CFB - implementare)
    - serverul transmite datele la procesul corespunzator clientului B (pipe) unde sunt criptate folosind
      K2, IV2 (CBC/CFB - implementare)
    - serverul transmite clientului B numarul de blocuri, lungimea unui bloc cryptotext, respectiv
      cate un bloc de cryptotext(pentru fiecare bloc)
    - clientul B primeste datele, le decripteaza folosind K si IV (CBC/CFB - implementare) si le afiseaza pe ecran
    - clientul B trimite cod de confirmare serverului, iar serverul il trimite mai departe clientului A
    - clientul A CONFIRMA

Observatie:
    -padding cu un numar de cifre in cazul in care nu esti satisfacuta lungimea unui bloc
    -ex: text[0123...k], 0123 -> pana lungimea unui bloc este 15 bytes, k -> lungime 16 bytes, numarul de cifre adaugate


CFB/CBC:
    - pentru simplitate s-a considerat functia de criptare XOR (nu se recomanda in practica, trebuie functie complexa)

CBC: c = m[i] xor iv[i%16], cryptotext = c xor key[i%16];
CFB: c = key[i%16] xor iv[i%16], cryptotext = c xor m[i];
