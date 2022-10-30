const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const CryptoJS = require("crypto-js");
const EncryptRsa = require('encrypt-rsa').default;

dotenv.config();

const PORT = process.env.PORT;
const cookieLifeTime = 1000 * 60 * 60;
const filesDir = './files/';
const encryptRsa = new EncryptRsa();

const aesKeys = {};

const app = express();

const corsOptions = {
    origin: process.env.CLIENT_HOST,
    credentials: true,
    allowedHeaders: 'Origin, X-Requested-With, Content-Type, Accept',
    methods: 'GET, POST, OPTIONS, DELETE'
};

const genSessionKey = (length) => {
    let result = '';
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const charactersLength = characters.length;

    for (let i = 0; i < length; i++ ) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }

    return result;
}

app.use(cors(corsOptions));
app.use(cookieParser());
app.use(express.json());

app.use(['/files', '/files/:fileName'], (req, res, next) => {
    if (!req.cookies.encryptedAesKey || !aesKeys[req.cookies.encryptedAesKey]) {
        console.log('error');
        res.cookie('encryptedAesKey', '', { maxAge: 0 });
        res.status(403).json({ message: 'Add rsa key' });
    } else {
        next();
    }
});

const adaptResponse = (cookies, response) => {
    const { encryptedAesKey } = cookies;
    const aesKey = aesKeys[encryptedAesKey];
    const stringResponse = JSON.stringify(response);

    return {
        message: CryptoJS.AES.encrypt(stringResponse, aesKey).toString()
    };
};

const parseRequest = (cookies, request) => {
    const { encryptedAesKey } = cookies;
    const aesKey = aesKeys[encryptedAesKey];

    const stringRequest = CryptoJS.AES.decrypt(request.message, aesKey).toString(CryptoJS.enc.Utf8);
    const adaptedRequest = JSON.parse(stringRequest);

    return adaptedRequest;
}

app.post('/', async (req, res) => {
    const { rsa: clientPubRsa } = req.body;

    if (!clientPubRsa) {
        res.status(403).json({ message: 'Add rsa key' });
    }

    const sessionKey = genSessionKey(10);
    const encryptedAesKey = encryptRsa.encryptStringWithRsaPublicKey({
        text: sessionKey,
        publicKey: clientPubRsa
    });

    aesKeys[encryptedAesKey] = sessionKey;

    res.cookie('encryptedAesKey', encryptedAesKey, { sameSite: 'none', secure: true, maxAge: cookieLifeTime });

    res.status(203).json({ message: 'cookies added' });
});

app.get('/files', (req, res) => {
    const files = fs.readdirSync(filesDir);
    res.json(adaptResponse(req.cookies, { files: files }));
});

app.get('/files/:fileName', (req, res) => {
    try {
        const path = `${filesDir}${req.params.fileName}`;
        if (fs.existsSync(path)) {
            res.json(adaptResponse(req.cookies, { file: fs.readFileSync(path, 'utf8') }));
        } else {
            res.json(adaptResponse(req.cookies, { file: '' }));
        }
    }
    catch (err) {
        res.status(403).json({ message: 'File doesn\'t exists' });
    }
});

app.post('/files/:fileName', (req, res) => {
    try {
        const { fileName } = req.params;
        const { file } = parseRequest(req.cookies, req.body);

        fs.writeFileSync(`${filesDir}${fileName}`, file);

        res.status(203).json({ message: 'File updated' });
    }
    catch (err) {
        res.status(403).json({ message: 'File doesn\'t exists' });
    }
});

app.delete('/files/:fileName', (req, res) => {
    try {
        const { fileName } = req.params;

        fs.unlinkSync(`${filesDir}${fileName}`);

        res.status(203).json({ message: 'File updated' });
    }
    catch (err) {
        res.status(403).json({ message: 'File doesn\'t exists' });
    };
});

app.listen(PORT, () => {
    console.log(`Server listening on ${PORT}`);
});
