import base64
import json
import os
import requests
import socket
from fastapi import FastAPI, Request, Response
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = FastAPI()

# =====================================================================
# 1. CARGA DE LA LLAVE PRIVADA RSA
# =====================================================================
# Asegúrate de tener tu archivo 'private.pem' en el mismo directorio.
# Esta llave nunca debe exponerse ni subirse a repositorios públicos.
try:
    with open("clave_privada_waba.pem", "rb") as key_file:
        private_key = load_pem_private_key(
            key_file.read(),
            password=None,
        )
except FileNotFoundError:
    print("⚠️ Advertencia: No se encontró el archivo clave_privada_waba.pem. El webhook fallará al recibir Flows.")
    private_key = None


# =====================================================================
# 2 y 3. WEBHOOK Y DESENCRIPTACIÓN DE LOS FLOWS (RECIBIR MENSAJES)
# =====================================================================
@app.get("/")
async def verify_webhook(request: Request):
    """
    Endpoint de verificación (Challenge Handshake) para Facebook.
    Responde con el 'hub.challenge' si el token coincide.
    """
    
    # Parámetros obligatorios que envía Facebook
    challenge_token = request.query_params.get("hub.challenge")
    verify_token = request.query_params.get("hub.verify_token")
    
    # ⚠️ IMPORTANTE: Este token debe coincidir con el configurado en Facebook
    expected_verify_token = "B0arLqVEXmV69kKyIZ6llUPP6FsYUkPQLuyhdIFEMEwv6m6UZsl793ExBaVDFbuO"
    
    if verify_token == expected_verify_token:
        print("✅ Challenge exitoso: El token coincide. Activación completada.")
        # Respondemos con el challenge para confirmar la conexión a Meta
        return Response(status_code=200, content=challenge_token)
    else:
        print("❌ Challenge fallido: El token NO coincide.")
        # Respondemos con error para que Meta vuelva a intentar o marque fallo
        return Response(status_code=403, content="Invalid Verify Token")


@app.post("/webhook")
async def whatsapp_webhook(request: Request):
    """
    Este endpoint atrapa los envíos del formulario de WhatsApp Flows.
    """
    dominio_resuelto = "No se pudo resolver"
    # 1. Obtener la IP real del backend cliente
    ip_cliente = request.headers.get("X-Forwarded-For")
    if ip_cliente:
        ip_cliente = ip_cliente.split(",")[0].strip()
    else:
        ip_cliente = request.client.host if request.client else None

    # 2. Intentar resolver el dominio mediante DNS Inverso
    if ip_cliente:
        try:
            # socket.gethostbyaddr devuelve una tupla; el primer elemento es el dominio principal
            dominio_resuelto = socket.gethostbyaddr(ip_cliente)[0]
        except socket.herror:
            # La IP no tiene un registro PTR configurado en su DNS
            dominio_resuelto = f"IP: {ip_cliente} (Sin registro DNS)"
            
    print(f'Dominio: {dominio_resuelto}')
    try:
        # Extraer el JSON que envía Meta
        body = await request.json()
        print(body) 
        # Validar que es un payload encriptado de Flows (Omitimos mensajes de texto normales aquí)
        if "encrypted_flow_data" not in body:
            # Aquí podrías manejar mensajes estándar o notificaciones de estado
            return {"status": "active"}
            
        encrypted_aes_key_b64 = body.get("encrypted_aes_key")
        encrypted_flow_data_b64 = body.get("encrypted_flow_data")
        initial_vector_b64 = body.get("initial_vector")
        
        # Paso A: Decodificar de Base64 a Bytes
        encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
        encrypted_flow_data = base64.b64decode(encrypted_flow_data_b64)
        initial_vector = base64.b64decode(initial_vector_b64)
        
        # Paso B: Desencriptar la llave AES usando nuestra Llave Privada RSA
        # Meta usa cifrado OAEP con SHA256 y función generadora de máscaras (MGF1)
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Paso C: Desencriptar el Payload (Datos del Flow) usando la llave AES descubierta (AES-GCM)
        aesgcm = AESGCM(aes_key)
        # En la librería cryptography, AESGCM.decrypt requiere (nonce/IV, datos_con_tag_incluido, datos_asociados)
        decrypted_data_bytes = aesgcm.decrypt(initial_vector, encrypted_flow_data, None)
        # Convertimos los bytes desencriptados a un Diccionario Python
        decrypted_data = json.loads(decrypted_data_bytes.decode('utf-8'))
        print("✅ Datos exitosamente desencriptados del Flow:")
        print(json.dumps(decrypted_data, indent=2))
        
        if decrypted_data.get("action") == "ping":
            response_payload = {
                "data": {
                    "status": "active",
                }
            }
        elif decrypted_data.get("action") == "INIT":
            # Extraemos el token si pasaste algún ID o información en él
            flow_token = decrypted_data.get("flow_token") 
            
            # Estructura requerida por Meta WhatsApp Flows
            response_payload = {
                "version": decrypted_data.get("version", "3.0"), # Debe coincidir con la versión de la petición
                "action": "navigate",     # Le indicamos a la app que navegue a la pantalla
                "screen": "QUESTION_ONE", # Reemplaza con el ID exacto de tu Flow JSON
                "data": {
                    "tarjeta": "",
                    "vencimiento": "",
                    "rfc": ""
                }
            }
            print(json.dumps(response_payload, indent=2))
            #return Response(status_code=200, content=json.dumps(response_payload), media_type="text/plain")
        else:
            response_payload = {
                "screen": "SUCCESS",
                "data": {
                    "extension_message_response": {
                        "params": {
                            "flow_token": decrypted_data.get("flow_token")
                        }
                    }
                }
            }
            print(json.dumps(response_payload, indent=2))
        
        # =====================================================================
        # 4. ENCRIPTAR LA RESPUESTA Y DEVOLVERLA A META
        # =====================================================================
        
        response_bytes = json.dumps(response_payload).encode('utf-8')
        
        # Meta exige que invirtamos los bits del IV (Vector de Inicialización) para la respuesta
        flipped_iv = bytes(~b & 0xFF for b in initial_vector)
        
        # Encriptamos la respuesta con la misma llave AES (y el nuevo IV invertido)
        encrypted_response_bytes = aesgcm.encrypt(flipped_iv, response_bytes, None)
        
        # Codificamos a Base64 para que viaje de forma segura por HTTP
        encrypted_response_b64 = base64.b64encode(encrypted_response_bytes).decode('utf-8')
        
        # MUY IMPORTANTE: WhatsApp Flows exige que el endpoint devuelva texto plano 
        # con la cadena Base64, NO un JSON.
        return Response(status_code=200, content=encrypted_response_b64, media_type="text/plain")
        
    except Exception as e:
        print(f"❌ Error procesando el webhook: {e}")
        # Retornar error 500 informará a Meta que hubo un problema y mostrará error en el celular
        response_payload = {
            "data": {
                "status": "active",
            }
        }
        response_bytes = json.dumps(response_payload).encode('utf-8')
        # Meta exige que invirtamos los bits del IV (Vector de Inicialización) para la respuesta
        flipped_iv = bytes(~b & 0xFF for b in initial_vector)
        aesgcm = AESGCM(aes_key)
        # Encriptamos la respuesta con la misma llave AES (y el nuevo IV invertido)
        encrypted_response_bytes = aesgcm.encrypt(flipped_iv, response_bytes, None)
        
        # Codificamos a Base64 para que viaje de forma segura por HTTP
        encrypted_response_b64 = base64.b64encode(encrypted_response_bytes).decode('utf-8')
        return Response(status_code=200, content=encrypted_response_b64)

@app.post("/")
async def webhookroot(request: Request):
    try:
        # Extraer el JSON que envía Meta
        body = await request.json()
        print(body) 
    except Exception as e:
        print(f"❌ Error procesando el webhook: {e}")
        
    send_whatsapp_flow_template("525513686487","activar_tarjeta","token_unico_123")
    return Response(status_code=200, content="Exito")


# =====================================================================
# 5. DETONAR UNA PLANTILLA CON EL BOTÓN DEL FLOW
# =====================================================================
def send_whatsapp_flow_template(phone_number: str, template_name: str, flow_token: str = "token_unico_123"):
    """
    Esta función envía de forma proactiva la plantilla que invita al usuario a abrir el Flow.
    """
    # Preferentemente cargar estas variables de entorno (.env)
    # PHONE_NUMBER_ID = os.environ.get("PHONE_NUMBER_ID", "TU_PHONE_NUMBER_ID")
    # ACCESS_TOKEN = os.environ.get("WHATSAPP_ACCESS_TOKEN", "TU_ACCESS_TOKEN")

    PHONE_NUMBER_ID = '1229158673605024'
    ACCESS_TOKEN = 'EAAV9gZB0xn7YBRzAOAWDwYY5fHMWJFclkXM2g2mNjhTZCs8xhkPcb0ia94LMCpUB7OJqlQXEgCr4vAcchNxlZAqduauWjz1DcDaO6Ksdwg49CMKevRv6xdCWAkIc7Qj7pt5R7CZAZAZAYA7XH3NYX9IGK2rUADig8R0Xr8JMiBcKtG6VlZBZBS1p95iFVGUpoAZDZD'
    
    url = f"https://graph.facebook.com/v18.0/{PHONE_NUMBER_ID}/messages"
    
    headers = {
        "Authorization": f"Bearer {ACCESS_TOKEN}",
        "Content-Type": "application/json"
    }
    
    # Este es el Payload estándar para detonar un HSM (Plantilla) que incluye un Flow
    payload = {
        "messaging_product": "whatsapp",
        "to": f"{phone_number}",
        "recipient_type": "individual",
        "type": "interactive",
        "interactive": {
            "type": "flow",
            "header": {
                "type": "text",
                "text": "Agregar Tarjeta"
            },
            "body": {
                "text": "Datos de la tarjeta"
            },
            "action": {
                "name": "flow",
                "parameters": {
                    "flow_message_version": "3",
                    "flow_action": "data_exchange",
                    "flow_token": f"{flow_token}",
                    "flow_name": f"{template_name}",
                    "flow_cta": "Ingresar datos"
                }
            }
        }
    }
    print(json.dumps(payload, indent=2))
    # Enviamos el POST a la API Graph de Meta
    response = requests.post(url, headers=headers, json=payload)
    
    if response.status_code == 200:
        print(f"✅ Plantilla Flow enviada a {phone_number}")
    else:
        print(f"❌ Error al enviar plantilla: {response.text}")
        
    return response.json()


