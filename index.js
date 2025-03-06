const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");

require("dotenv").config();

const serviceAccount = {
  type: process.env.TYPE,
  project_id: process.env.PROJECT_ID,
  private_key_id: process.env.PRIVATE_KEY_ID,
  private_key: process.env.PRIVATE_KEY.replace(/\\n/g, "\n"),
  client_email: process.env.CLIENT_EMAIL,
  client_id: process.env.CLIENT_ID,
  auth_uri: process.env.AUTH_URI,
  token_uri: process.env.TOKEN_URI,
  auth_provider_x509_cert_url: process.env.AUTH_PROVIDER_CERT_URL,
  client_x509_cert_url: process.env.CLIENT_CERT_URL,
  universe_domain: process.env.UNIVERSE_DOMAIN,
};

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();
const app = express();

app.use(cors());
app.use(express.json());

const verifyToken = (allowedRoles) => async (req, res, next) => {
  console.log("Iniciando verificación de token");
  const token = req.headers["authorization"]?.split(" ")[1];
  console.log("Headers", req.headers);

  if (!token) {
    console.log("Token no proporcionado");
    return res
      .status(401)
      .json({ message: "Acceso denegado. Token no proporcionado." });
  }

  console.log("Token recibido:", token);

  try {
    const db = admin.firestore();
    const tokensRef = db.collection("tokensVerification");
    const tokenSnapshot = await tokensRef.where("token", "==", token).get();

    if (tokenSnapshot.empty) {
      console.log("Token inválido o no encontrado");
      return res
        .status(401)
        .json({ message: "Token inválido o no encontrado." });
    }

    const tokenData = tokenSnapshot.docs[0].data();
    console.log("Datos del token:", tokenData);

    const now = new Date();
    if (new Date(tokenData.expiresAt) < now) {
      console.log("Token expirado");
      return res.status(401).json({ message: "Token ha expirado." });
    }

    //Obtenemos el usuario desde la colección users
    const usersRef = db.collection("users");
    const userSnapshot = await usersRef.doc(tokenData.userId).get();

    if (!userSnapshot.exists) {
      console.log("Usuario no encontrado");
      return res.status(401).json({ message: "Usuario no encontrado." });
    }

    const userData = userSnapshot.data();
    console.log("Datos del usuario:", userData);

    if (!allowedRoles.includes(userData.role)) {
      console.log("Permisos insuficientes. Rol del usuario:", userData.role);
      return res
        .status(403)
        .json({ message: "Acceso denegado. Permisos insuficientes." });
    }

    console.log("Token verificado exitosamente");
    req.user = { id: tokenData.userId, role: userData.role };
    next();
  } catch (error) {
    console.error("Error en la verificación del token:", error);
    res
      .status(500)
      .json({ message: "Error al verificar el token.", error: error.message });
  }
};

app.get("/", (req, res) => {
  res.send("Groups service running!");
});

//Obtenemos todos los grupos a los que pertenece el usuario
app.get("/groups", verifyToken(["admin", "mortal"]), async (req, res) => {
  try {
    const groupsRef = db.collection("groups");

    //Consultar los grupos en los que el usuario es participante
    const groupsSnapshotByParticipant = await groupsRef
      .where("participantes", "array-contains", req.user.id)
      .get();

    //Consultar los grupos en los que el usuario es el creador
    const groupsSnapshotByCreator = await groupsRef
      .where("createdBy", "==", req.user.id)
      .get();

    const role = req.user.role;

    //Combinar los resultados de ambas consultas
    const groups = [];

    groupsSnapshotByParticipant.docs.forEach((doc) => {
      if (!groups.some((group) => group.id === doc.id)) {
        groups.push({
          id: doc.id,
          ...doc.data(),
        });
      }
    });

    groupsSnapshotByCreator.docs.forEach((doc) => {
      if (!groups.some((group) => group.id === doc.id)) {
        groups.push({
          id: doc.id,
          ...doc.data(),
        });
      }
    });

    if (groups.length === 0) {
      return res.status(200).json({ groups: [], role }); //Devuelve un array vacío si no hay grupos
    }

    return res.status(200).json({ groups, role });
  } catch (error) {
    console.error("Error al obtener los grupos:", error);
    return res
      .status(500)
      .json({ message: "Error en el servidor", error: error.message });
  }
});

app.post("/createGroup", verifyToken(["admin"]), async (req, res) => {
  try {
    const { name, participantes } = req.body;
    const createdBy = req.user.id;

    const groupRef = db.collection("groups");
    const newGroup = {
      name,
      participantes,
      createdBy,
      createdAt: new Date(),
    };

    const docRef = await groupRef.add(newGroup);
    return res.status(201).json({ group: { id: docRef.id, ...newGroup } });
  } catch (error) {
    console.error("Error al crear el grupo:", error);
    return res.status(500).json({ message: "Error en el servidor" });
  }
});

app.post(
  "/groups/:groupId/addParticipant",
  verifyToken(["admin"]),
  async (req, res) => {
    try {
      const { groupId } = req.params;
      const { participantId } = req.body;

      const groupRef = db.collection("groups").doc(groupId);
      const groupDoc = await groupRef.get();

      if (!groupDoc.exists) {
        return res.status(404).json({ message: "Grupo no encontrado" });
      }

      const groupData = groupDoc.data();
      const updatedParticipants = [
        ...new Set([...groupData.participantes, participantId]),
      ];

      await groupRef.update({ participantes: updatedParticipants });

      res.status(200).json({ message: "Participante añadido con éxito" });
    } catch (error) {
      console.error("Error al añadir participante:", error);
      res.status(500).json({ message: "Error en el servidor" });
    }
  }
);

const PORT = process.env.GROUPS_SERVICE_PORT || 5002;
app.listen(PORT, () => {
  console.log(`Groups service running on http://localhost:${PORT}`);
});
