# Generador y Gestor de Contraseñas

Una aplicación de escritorio desarrollada en Python que permite generar contraseñas seguras y gestionar su almacenamiento de forma segura. La idea fue crear algo simple que pueda aportar a la idea de almacenar tus claves de manera local sin tener que depender de los servicios como iCloud Keychain, LastPass, 1Password, etc. Que si bien son servicios seguros, no dejan de ser servicios que almacenan contraseñas en servidores en linea ¿Que mejor idea que ser vos el que las almacene por su cuenta?

## Características

- **Generación de Contraseñas Seguras**
  - Longitud personalizable
  - Opción para incluir caracteres especiales
  - Animación al generar la contraseña

- **Almacenamiento Seguro**
  - Encriptación de contraseñas
  - Sistema de claves pública/privada
  - Búsqueda de contraseñas almacenadas
  - Visualización de detalles con doble clic

- **Seguridad**
  - Sistema de 3 intentos para accesos
  - Bloqueo automático después de intentos fallidos
  - Mensajes informativos de intentos restantes
  - Protección de contraseñas con claves de acceso

- **Interfaz Gráfica**
  - Diseño moderno y fácil de usar
  - Ventanas modales para operaciones sensibles
  - Mensajes de error informativos
  - Búsqueda en tiempo real

## Requisitos

- Python 3.x
- Tkinter (incluido en la mayoría de las instalaciones de Python)
- Dependencias listadas en `requirements.txt`

## Instalación

1. Clonar el repositorio:
```bash
git clone https://github.com/felip3-14/generador-de-contrasenas.git
cd generador-de-contrasenas
```

2. Crear y activar entorno virtual:
```bash
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate
```

3. Instalar dependencias:
```bash
pip install -r requirements.txt
```

## Uso

1. Ejecutar la aplicación:
```bash
python main.py
```

2. Al iniciar, se solicitará la clave pública para acceder al sistema.

3. Para generar una contraseña:
   - Establecer la longitud deseada
   - Seleccionar caracteres especiales
   - Hacer clic en "Generar Contraseña"

4. Para guardar una contraseña:
   - Ingresar plataforma y usuario
   - Hacer clic en "Guardar Contraseña"

5. Para ver una contraseña almacenada:
   - Hacer doble clic en la entrada deseada
   - Ingresar la clave privada cuando se solicite

## Seguridad

- La aplicación utiliza un sistema de claves asimetricas (pública/privada)
- Las contraseñas se almacenan de forma encriptada
- Se implementa un sistema de bloqueo después de 3 intentos fallidos
- Las claves se pueden cambiar desde el menú de configuración
