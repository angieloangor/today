import io
import re

import qrcode
import streamlit as st

from web_app import auth_service, security


st.set_page_config(page_title="Acceso seguro", page_icon="🔐", layout="centered")

st.title("Acceso seguro")


if "authenticated_user" in st.session_state:
    user_profile = st.session_state["authenticated_user"]
    if not isinstance(user_profile, dict):
        del st.session_state["authenticated_user"]
        st.info("La sesión anterior caducó. Inicia sesión nuevamente.")
    else:
        st.subheader(f"Hola, {user_profile['name']}")
        st.success("Sesión iniciada correctamente")
        st.markdown("### Tus datos")
        st.write(f"**Nombre:** {user_profile['name']}")
        st.write(f"**Correo electrónico:** {user_profile['email']}")
        st.write("**Verificación en dos pasos:** Activada con Google Authenticator")
        if st.button("Cerrar sesión"):
            del st.session_state["authenticated_user"]
            st.rerun()
        st.stop()


pending_registration = st.session_state.get("pending_registration")
if pending_registration:
    st.subheader("Configura Google Authenticator")
    st.write(
        "Escanea el código QR con Google Authenticator y confirma la configuración "
        "con el código de seis dígitos que aparece en la aplicación."
    )
    qr_image = qrcode.make(
        auth_service.provisioning_uri(
            pending_registration["email"], pending_registration["totp_secret"]
        )
    )
    qr_buffer = io.BytesIO()
    qr_image.save(qr_buffer, format="PNG")
    st.image(qr_buffer.getvalue(), caption="QR de configuración TOTP", width=240)

    with st.form("confirmar-otp"):
        otp_code = st.text_input("Código de 6 dígitos", max_chars=6)
        confirm_setup = st.form_submit_button("Activar y continuar")

    if confirm_setup:
        if not auth_service.verify_totp(
            pending_registration["totp_secret"], otp_code
        ):
            st.error("El código no es válido. Revisa la hora del dispositivo e inténtalo otra vez.")
        elif auth_service.create_user(
            pending_registration["name"],
            pending_registration["email"],
            pending_registration["password_hash"],
            pending_registration["totp_secret"],
        ):
            st.session_state["authenticated_user"] = {
                "name": pending_registration["name"],
                "email": pending_registration["email"],
            }
            del st.session_state["pending_registration"]
            st.rerun()
        else:
            st.error("Ya existe una cuenta con ese correo. Inicia sesión.")

    if st.button("Cancelar registro"):
        del st.session_state["pending_registration"]
        st.rerun()
else:
    register_tab, login_tab = st.tabs(["Crear cuenta", "Iniciar sesión"])

    with register_tab:
        with st.form("registro"):
            name = st.text_input("Nombre")
            email = st.text_input("Correo electrónico")
            password = st.text_input("Contraseña", type="password")
            password_confirmation = st.text_input(
                "Confirmar contraseña", type="password"
            )
            register = st.form_submit_button("Continuar con la configuración OTP")

        if register:
            normalized_email = email.strip().lower()
            if not name.strip():
                st.error("Escribe tu nombre.")
            elif not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", normalized_email):
                st.error("Escribe un correo electrónico válido.")
            elif policy_error := security.password_policy_error(
                password, normalized_email, name
            ):
                st.error(policy_error)
            elif password != password_confirmation:
                st.error("Las contraseñas no coinciden.")
            else:
                st.session_state["pending_registration"] = {
                    "name": name.strip(),
                    "email": normalized_email,
                    "password_hash": auth_service.hash_password(password),
                    "totp_secret": auth_service.create_totp_secret(),
                }
                st.rerun()

    with login_tab:
        with st.form("inicio-sesion"):
            login_email = st.text_input("Correo electrónico", key="login_email")
            login_password = st.text_input(
                "Contraseña", type="password", key="login_password"
            )
            login_otp = st.text_input(
                "Código de Google Authenticator", max_chars=6, key="login_otp"
            )
            login = st.form_submit_button("Iniciar sesión")

        if login:
            user_profile = auth_service.authenticate(
                login_email, login_password, login_otp
            )
            if user_profile is None:
                st.error("Correo, contraseña o código OTP incorrectos.")
            else:
                st.session_state["authenticated_user"] = user_profile
                st.rerun()


st.markdown("---")
st.caption("© 2025 Nuu | Todos los derechos reservados")