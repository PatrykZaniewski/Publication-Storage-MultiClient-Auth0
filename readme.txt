Przed uruchomieniem dockera należy przejść do folderu z projektem.
Następnie, należy uruchomić kontenery poleceniem:

docker-compose -f docker-compose.yml up --build

W celu połączenia się z aplikacją należy przejść pod adres https://web.company.com.
Domyślne dane logowania:

login: smiglowiec@szturmowy.pl
hasło: apache123!

login: czolg@bojowy.pl
hasło: abrams123!

Pliki wysyłane przez użytkowników znajdują się w folderze tmp/<nazwa_użytkownika>/<nazwa_publikacji> w głównym katalogu projektu.
Lokalizację katalogu można zmienić w docker-compose.yml poprzez edycję kontenera "web". W sekcji volumes należy zmienić lokalizację tmp.