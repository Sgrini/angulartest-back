const express = require("express");
const cors = require("cors");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const jwtUtils = require("jsonwebtoken");
const interceptor = require("./middleware/jwt-interceptor");

const app = express();

// Configuration de la base de données
const connection = mysql.createConnection({
  host: "localhost",
  port: 3307, //<-- optionnel si c'est le port par défaut (3306)
  user: "root",
  //password: "", //<--- ne pas mettre si vous n'avez pas de mot de passe
  database: "angulartest",
});

// Connexion à la base de données
connection.connect((err) => {
  if (err) {
    console.error("Erreur de connexion à la base de données :", err);
    return;
  }
  console.log("Connecté à la base de données MySQL");
});

app.use(cors());

app.use(express.json()); // permet d'envoyer et recevoir du JSON (via les en-tête content-type et accept-content)

app.get("/", (requete, resultat) => {
  resultat.send("<h1>C'est une API il y a rien a voir ici</h1>");
});

app.get("/cours/liste", (requete, resultat) => {
  connection.query("SELECT * FROM cours", (err, lignes) => {
    //en cas d'erreur sql ou d'interuption de connexion avec la bdd
    if (err) {
      console.error(err);
      return resultat.sendStatus(500);
    }

    return resultat.json(lignes);
  });
});

app.get("/cours/:id", (requete, resultat) => {
  connection.query(
    "SELECT * FROM cours WHERE id = ?",
    [requete.params.id],
    (err, lignes) => {
      //en cas d'erreur sql ou d'interuption de connexion avec la bdd
      if (err) {
        console.error(err);
        return resultat.sendStatus(500);
      }

      //si l'id du cours est inconnu
      if (lignes.length == 0) {
        return resultat.sendStatus(404);
      }

      return resultat.json(lignes[0]);
    }
  );
});

app.put("/cours/:id", interceptor, (requete, resultat) => {
  const cours = requete.body;
  cours.id = requete.params.id;

  if (requete.user.role != "profs" && requete.user.role != "administration") {
    return resultat.sendStatus(403);
  }

  if (
    cours.nom == null ||
    cours.nom == "" ||
    cours.nom.length > 20 ||
    cours.description.length > 50
  ) {
    //validation
    return resultat.sendStatus(400); //bad request
  }

  //verification si le nom du cours existe déjà
  connection.query(
    "SELECT * FROM cours WHERE nom = ? AND id != ?",
    [cours.nom, cours.id],
    (err, lignes) => {
      if (lignes.length > 0) {
        return resultat.sendStatus(409); //conflict
      }

      connection.query(
        "UPDATE cours SET nom = ?, description = ? WHERE id = ?",
        [cours.nom, cours.description, cours.id],
        (err, lignes) => {
          if (err) {
            console.error(err);
            return resultat.sendStatus(500); //internal server error
          }

          return resultat.status(200).json(cours); //ok
        }
      );
    }
  );
});

app.post("/cours", interceptor, (requete, resultat) => {
  const cours = requete.body;

  if (requete.user.role != "profs" && requete.user.role != "administration") {
    return resultat.sendStatus(403);
  }

  if (
    cours.nom == null ||
    cours.nom == "" ||
    cours.nom.length > 20 ||
    cours.description.length > 50
  ) {
    //validation
    return resultat.sendStatus(400); //bad request
  }

  //verification si le nom du cours existe déjà
  connection.query(
    "SELECT * FROM cours WHERE nom = ?",
    [cours.nom],
    (err, lignes) => {
      if (lignes.length > 0) {
        return resultat.sendStatus(409); //conflict
      }

      connection.query(
        "INSERT INTO cours (nom, description, id_createur) VALUES (?, ?, ?)",
        [cours.nom, cours.description, requete.user.id],
        (err, lignes) => {
          if (err) {
            console.error(err);
            return resultat.sendStatus(500); //internal server error
          }

          resultat.status(201).json(cours); //created
        }
      );
    }
  );
});

app.delete("/cours/:id", interceptor, (requete, resultat) => {
  //on recupere le cours
  connection.query(
    "SELECT * FROM cours WHERE id = ?",
    [requete.params.id],
    (erreur, lignes) => {
      //si il y a eu une erreur
      if (erreur) {
        console.error(err);
        return resultat.sendStatus(500); //internal server error
      }

      //si l'id du cours est inconnu
      if (lignes.length == 0) {
        return resultat.sendStatus(404);
      }

      //on vérifie si l'utilisateur connecté est le propriétaire
      const estProprietaire =
        requete.user.role == "profs" &&
        requete.user.id == lignes[0].id_createur;
      //si il n'est ni propriétaire du cours, ni administrateur
      if (!estProprietaire && requete.user.role != "administration") {
        return resultat.sendStatus(403);
      }

      //on supprime le cours
      connection.query(
        "DELETE FROM cours WHERE id = ?",
        [requete.params.id],
        (erreur, lignes) => {
          //si il y a eu une erreur
          if (erreur) {
            console.error(err);
            return resultat.sendStatus(500); //internal server error
          }

          //204 = no content = tout c'est bien passé, mais il n'y a rien dans le corp de la réponse
          return resultat.sendStatus(204);
        }
      );
    }
  );
});

app.post("/inscription", (requete, resultat) => {
  const utilisateur = requete.body;

  const passwordHash = bcrypt.hashSync(utilisateur.password, 10);

  connection.query(
    "INSERT INTO utilisateur(email, password, role_id) VALUES (? , ?, ?)",
    [utilisateur.email, passwordHash, 2],
    (err, retour) => {
      if (err && err.code == "ER_DUP_ENTRY") {
        return resultat.sendStatus(409); //conflict
      }

      if (err) {
        console.error(err);
        return resultat.sendStatus(500); //internal server error
      }

      utilisateur.id = retour.insertId;
      resultat.json(utilisateur);
    }
  );
});

app.post("/connexion", (requete, resultat) => {
  connection.query(
    `SELECT u.id, u.email, u.password, r.nom 
      FROM utilisateur u 
      JOIN role r ON u.role_id = r.id 
      WHERE email = ?`,
    [requete.body.email],
    (erreur, lignes) => {
      if (erreur) {
        console.error(erreur);
        return resultat.sendStatus(500); //internal server error
      }

      console.log(lignes);

      //si l'email est inexistant
      if (lignes.length === 0) {
        return resultat.sendStatus(401);
      }

      const motDePasseFormulaire = requete.body.password;
      const motDePasseHashBaseDeDonnees = lignes[0].password;

      const compatible = bcrypt.compareSync(
        motDePasseFormulaire,
        motDePasseHashBaseDeDonnees
      );

      if (!compatible) {
        return resultat.sendStatus(401);
      }

      return resultat.send(
        jwtUtils.sign(
          {
            sub: requete.body.email,
            role: lignes[0].nom,
            id: lignes[0].id,
          },
          "azerty123"
        )
      );
    }
  );
});

app.listen(5000, () => console.log("Le serveur écoute sur le port 5000 !!"));
