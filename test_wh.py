import base64
import json
import os
import requests
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
@app.post("/webhook")
async def whatsapp_webhook(request: Request):
    """
    Este endpoint atrapa los envíos del formulario de WhatsApp Flows.
    """
    try:
        # Extraer el JSON que envía Meta
        body = await request.json()
    
        # Validar que es un payload encriptado de Flows (Omitimos mensajes de texto normales aquí)
        if "encrypted_flow_data" not in body:
            # Aquí podrías manejar mensajes estándar o notificaciones de estado
            return {"status": "ignored"}
            
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
        
        # =====================================================================
        # 4. ENCRIPTAR LA RESPUESTA Y DEVOLVERLA A META
        # =====================================================================
        # Preparamos la acción que el celular del usuario debe hacer ahora
        # Por ejemplo, avanzar a una pantalla llamada "SUCCESS_SCREEN"
        response_payload = {
            data: {
                    status: "active",
                  },
        }
        response_bytes = json.dumps(response_payload).encode('utf-8')
        
        # Meta exige que invirtamos los bits del IV (Vector de Inicialización) para la respuesta
        flipped_iv = bytes(~b & 0xFF for b in initial_vector)
        
        # Encriptamos la respuesta con la misma llave AES (y el nuevo IV invertido)
        encrypted_response_bytes = aesgcm.encrypt(flipped_iv, response_bytes, None)
        
        # Codificamos a Base64 para que viaje de forma segura por HTTP
        encrypted_response_b64 = base64.b64encode(encrypted_response_bytes).decode('utf-8')
        
        # MUY IMPORTANTE: WhatsApp Flows exige que el endpoint devuelva texto plano 
        # con la cadena Base64, NO un JSON.
        return Response(content=encrypted_response_b64, media_type="text/plain")
        
    except Exception as e:
        print(f"❌ Error procesando el webhook: {e}")
        # Retornar error 500 informará a Meta que hubo un problema y mostrará error en el celular
        return Response(status_code=500, content="Error interno")


# =====================================================================
# 5. DETONAR UNA PLANTILLA CON EL BOTÓN DEL FLOW
# =====================================================================
def send_whatsapp_flow_template(phone_number: str, template_name: str, flow_token: str = "token_unico_123"):
    """
    Esta función envía de forma proactiva la plantilla que invita al usuario a abrir el Flow.
    """
    # Preferentemente cargar estas variables de entorno (.env)
    PHONE_NUMBER_ID = os.environ.get("PHONE_NUMBER_ID", "TU_PHONE_NUMBER_ID")
    ACCESS_TOKEN = os.environ.get("WHATSAPP_ACCESS_TOKEN", "TU_ACCESS_TOKEN")
    
    url = f"https://graph.facebook.com/v18.0/{PHONE_NUMBER_ID}/messages"
    
    headers = {
        "Authorization": f"Bearer {ACCESS_TOKEN}",
        "Content-Type": "application/json"
    }
    
    # Este es el Payload estándar para detonar un HSM (Plantilla) que incluye un Flow
    payload = {
        "messaging_product": "whatsapp",
        "to": phone_number,
        "type": "template",
        "template": {
            "name": template_name, 
            "language": {
                "code": "es_MX"  # Ajustar a la configuración de tu plantilla
            },
            "components": [
                {
                    "type": "button",
                    "sub_type": "flow",
                    "index": "0", # Representa el primer botón
                    "parameters": [
                        {
                            "type": "action",
                            "action": {
                                # Este token te será devuelto en el Webhook para rastrear la sesión del usuario
                                "flow_token": flow_token, 
                                "flow_action_data": {
                                    "on_click_action": {
                                        "name": "navigate",
                                        "payload": {
                                            "screen": "START_SCREEN" # La pantalla inicial que diseñaste en tu JSON de Flow
                                        }
                                    }
                                }
                            }
                        }
                    ]
                }
            ]
        }
    }
    
    # Enviamos el POST a la API Graph de Meta
    response = requests.post(url, headers=headers, json=payload)
    
    if response.status_code == 200:
        print(f"✅ Plantilla Flow enviada a {phone_number}")
    else:
        print(f"❌ Error al enviar plantilla: {response.text}")
        
    return response.json()
