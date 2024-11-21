# README: Proyecto de Ransomware Básico

## Descripción del Proyecto
Este repositorio contiene la implementación de un ransomware básico como parte del examen final de la asignatura de Criptografía en la Universidad del Norte. El proyecto simula la operación de un ransomware, aplicando conceptos fundamentales de criptografía estudiados durante el curso. **Advertencia: Este código es únicamente para propósitos educativos y de simulación. No debe ser utilizado en un entorno real ni con fines malintencionados.**

## Funcionalidades Implementadas
El ransomware implementa los siguientes pasos:
1. **Intercambio de claves asimétrico (AKE v.2):** 
   - Generación de certificados digitales que incluyen identidad y llave pública RSA de 2048 bits.
   - Uso del cifrado PKCS1_OAEP para la transferencia de una clave temporal de forma segura.
   - Uso de firmas digitales PKCS1_v1_5 para asegurar la integridad y autenticidad de las comunicaciones.

2. **Cifrado de archivos en la máquina víctima:**
   - Derivación de una clave simétrica mediante SHA-256 como KDF.
   - Cifrado de archivos con AES en modo CBC, incluyendo el vector de inicialización (IV) en los archivos cifrados.

3. **Notificación de rescate:**
   - Envío de un mensaje al usuario víctima indicando que los archivos han sido cifrados y cómo proceder para recuperarlos.

4. **Descifrado de archivos:**
   - Envío de instrucciones para derivar la clave de descifrado una vez realizado el pago.
   - Descifrado de los archivos y verificación de su integridad mediante comparación de hashes.

## Archivos Principales
1. **`victim.py`:** 
   - Simula el comportamiento de la máquina víctima.
   - Incluye la recepción del certificado del atacante, el descifrado de la clave temporal, y el descifrado de los archivos.

2. **`attacker.py`:**
   - Simula el comportamiento del atacante.
   - Incluye la generación de claves y certificados, el cifrado de archivos de la víctima, y el envío de las instrucciones de rescate y descifrado.
