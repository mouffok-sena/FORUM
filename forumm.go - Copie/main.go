package main

import (
	"database/sql"

	"html/template"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	_ "github.com/mattn/go-sqlite3"
)

// Ces variables sont utilisées pour la gestion de la base de données et des templates.
var (
	db        *sql.DB
	templates *template.Template
)

//Cette structure définit un modèle pour représenter un utilisateur avec les champs email, Username et Password.

type User struct {
	email    string
	Username string
	Password string
}

func main() {
	var err error
	//utilisation de css dans html (chemin d accées)
	http.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("css"))))
	http.Handle("/img/", http.StripPrefix("/img/", http.FileServer(http.Dir("img"))))
	http.Handle("/script/", http.StripPrefix("/script/", http.FileServer(http.Dir("script"))))
	// ouvrir la base de données
	db, err = sql.Open("sqlite3", "./db.sqlite")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	//C'est une requête SQL pour créer une table dans la base de données si elle n est pas crée
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			username TEXT NOT NULL,
			password TEXT NOT NULL,
			email TEXT NOT NULL
		);
	`)
	//si on vas rencontrer une erreur donc on ferme
	if err != nil {
		log.Fatal(err)
	}
	//parseglob il sert a recuperer tout les fichiers html
	//le must garantit la marche il arrete tout si le parseglob est faux
	templates = template.Must(template.ParseGlob("*.html"))
	//chemin d accees
	http.HandleFunc("/welcome.html", homeHandler)
	http.HandleFunc("/", acceuil)
	http.HandleFunc("/signup", signupHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	// il démarre le serveur HTTP en écoutant les requêtes entrantes sur le port 8080 et affiche un message de journal indiquant que le serveur a démarré.
	log.Println("Server started on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// La fonction homeHandler est une fonction de gestionnaire (handler) pour l'URL "/welcome.html".
func homeHandler(w http.ResponseWriter, r *http.Request) {

	err := templates.ExecuteTemplate(w, "welcome.html", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Son rôle est d'exécuter le template "index.html"
func acceuil(w http.ResponseWriter, r *http.Request) {

	err := templates.ExecuteTemplate(w, "index.html", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Elle est destinée à gérer les requêtes POST envoyées lorsqu'un utilisateur s'inscrit sur un site web.
func signupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// prendre la valeur de la forme
		username := r.FormValue("username")
		password := r.FormValue("password")
		email := r.FormValue("email")
		// Hash le mot de passe
		hashedPassword, err := hashPassword(password)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Creer un user
		user := User{email: email, Username: username, Password: hashedPassword}
		err = createUser(user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// se rendre sur la page d acceuil
		http.Redirect(w, r, "/welcome.html", http.StatusSeeOther)
		return
	}

	// exécuter un template et gèrer les éventuelles erreurs qui pourraient survenir lors de cette opération
	err := templates.ExecuteTemplate(w, "index.html", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// prendre la valeur de la forme
		username := r.FormValue("username")
		password := r.FormValue("password")

		// verifier si le user existe
		user, err := getUser(username)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if user == nil || !checkPasswordHash(password, user.Password) {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		// se rendre sur welcome.html
		http.Redirect(w, r, "/welcome.html", http.StatusSeeOther)
		return
	}

	// ce code exécute le template "index.html" et renvoie une réponse HTTP d'erreur lors de l'exécution du template.
	err := templates.ExecuteTemplate(w, "index.html", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	//Rediriger vers la page de connexion
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func createUser(user User) error {
	db, er := sql.Open("sqlite3", "./db.sqlite")
	if er != nil {
		log.Fatal(er)
	}
	defer db.Close()

	// Insérer le nouvel utilisateur dans la table des utilisateurs
	_, err := db.Exec("INSERT INTO users(username, email, password) VALUES (?,?,?)", user.Username, user.email, user.Password)
	return err
}

// La fonction getUser est une fonction qui récupère un utilisateur à partir de la table des utilisateurs en fonction du nom d'utilisateur.
func getUser(username string) (*User, error) {
	// Récupérer l'utilisateur depuis la table des utilisateurs en fonction du nom d'utilisateur
	row := db.QueryRow("SELECT id, username, password FROM users WHERE username = ?", username)

	var user User
	err := row.Scan(&user.email, &user.Username, &user.Password)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// envoie le hash du mot de passe ainsi que l'éventuelle erreur survenue lors de la génération du hash.
func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// st utilisée pour vérifier si un mot de passe en clair correspond à un hash donné.
func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
