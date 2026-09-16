require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');

const app = express();

app.use(cors());
app.use(express.json());

const MASTER_KEY = process.env.JSONBIN_KEY || "$2a$10$57GVHOh2wUkA/CAiSH0FXOspTxtZqzV/9iEzdKVYdgdpCDB0N7Fdu";
const BIN_ID = process.env.JSONBIN_BIN_ID || "6aab1011ac6210605ad6380c";
const API_URL = `https://api.jsonbin.io/v3/b/${BIN_ID}`;

app.get('/api/users', async (req, res) => {
    try {
        const response = await axios.get(`${API_URL}/latest`, {
            headers: { 'X-Master-Key': MASTER_KEY }
        });
        const users = response.data.record ? response.data.record.users : [];
        res.status(200).json({ success: true, data: users });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Gagal mengambil data dari cloud database.' });
    }
});

app.put('/api/users', async (req, res) => {
    try {
        const { users } = req.body;
        if (!Array.isArray(users)) {
            return res.status(400).json({ success: false, error: 'Format data tidak valid.' });
        }

        await axios.put(API_URL, { users: users }, {
            headers: {
                'Content-Type': 'application/json',
                'X-Master-Key': MASTER_KEY
            }
        });

        res.status(200).json({ success: true, message: 'Data berhasil diperbarui.' });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Gagal memperbarui data cloud database.' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server API Proxy aktif pada port ${PORT}`);
});
