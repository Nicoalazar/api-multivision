# MultivisionPlay Backend - Proxy mTLS y Desencriptación

## Descripción
Este servidor Node.js actúa como intermediario entre la página web y los servicios de MultivisionPlay. Su función principal es:

1. **Obtener las llaves de desencriptación** conectándose al servidor de verificación mediante mTLS (mutual TLS) con los certificados extraídos de la APK.
2. **Desencriptar** los datos encriptados (URLs de streaming, headers, licencias DRM, etc.) usando AES.
3. **Proxear** las listas de canales y otros endpoints para evitar problemas de CORS.

## Requisitos
- Node.js >= 18
- npm

## Instalación

```bash
cd multivision-backend
npm install
```

## Estructura del proyecto

```
multivision-backend/
├── server.js              # Servidor Express principal
├── package.json
├── certs/
│   ├── client.p12         # Certificado cliente para mTLS (del APK)
│   ├── ca.crt             # Certificado CA (del APK)
│   ├── client.pem         # Cert extraído (generado con openssl)
│   └── client-key.pem     # Key extraída (generado con openssl)
├── data/
│   ├── lista_premium.json # Cache de la lista premium (encriptada)
│   └── lista_basico.json  # Cache de la lista básica (encriptada)
└── README.md
```

## Ejecución

```bash
node server.js
```

El servidor arrancará en `http://localhost:3001` y automáticamente intentará obtener las llaves de desencriptación.

## API Endpoints

### Llaves
| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/api/keys/status` | Estado actual de las llaves |
| GET | `/api/keys/refresh` | Forzar re-obtención de llaves |

### Desencriptación
| Método | Ruta | Descripción |
|--------|------|-------------|
| POST | `/api/decrypt` | Desencriptar un string. Body: `{ "data": "base64..." }` |
| POST | `/api/encrypt` | Encriptar un string. Body: `{ "data": "texto" }` |
| POST | `/api/decrypt-batch` | Desencriptar múltiples campos. Body: `{ "fields": { "uri": "...", "headers": "..." } }` |

### Canales
| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/api/channels/premium` | Lista premium (encriptada) |
| GET | `/api/channels/basico` | Lista básica (encriptada) |
| GET | `/api/channels/premium/decrypted` | Lista premium desencriptada |
| GET | `/api/channels/basico/decrypted` | Lista básica desencriptada |

### Proxy
| Método | Ruta | Descripción |
|--------|------|-------------|
| ALL | `/api/proxy?url=...` | Proxy genérico para evitar CORS |

### Sistema
| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/api/health` | Health check |

## Flujo criptográfico

1. Se conecta a `https://179.43.126.108:7443/verify` con mTLS
2. Envía `{"ciphertext":"nrm7CAwtrvcktCJs8bUP8uhSX5uZJpjyPH+dfkYzeWM="}`
3. Recibe: `PASS_IV`, `PASS_KEY`, `CIPHER_ALGO`
4. Para desencriptar:
   - IV = MD5(PASS_IV) → 16 bytes
   - Key = SHA-256(PASS_KEY) → 32 bytes
   - Algoritmo: AES/CBC/PKCS5Padding → aes-256-cbc
   - Input: Base64 decode del texto encriptado
5. Para encriptar: proceso inverso

## Notas importantes
- Los certificados mTLS (`client.p12`, `ca.crt`) son necesarios para obtener las llaves
- El password del PKCS12 es: `PlayDigitalSas290114`
- Las llaves pueden cambiar periódicamente; el endpoint `/api/keys/refresh` permite re-obtenerlas
- El servidor debe correr en un entorno que pueda conectarse a la IP `179.43.126.108:7443`