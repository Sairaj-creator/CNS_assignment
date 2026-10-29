"""Streamlit web interface for X.509 PKI Chain Validation Simulator."""
import streamlit as st
import datetime as dt
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

# Import functions from the existing validation logic
from pki_chain_validation import build_pki, validate_chain, tamper, make_name, issue_cert

st.set_page_config(page_title="PKI Chain Validation", page_icon="🔐", layout="wide")

st.title("X.509 PKI Chain Validator")
st.markdown("A simulation of a three-level X.509 certificate chain (Root CA &rarr; Intermediate CA &rarr; End-user).")

if "pki" not in st.session_state:
    st.session_state.pki = None

if st.button("Generate PKI Chain"):
    st.session_state.pki = build_pki()
    st.success("New PKI chain generated successfully!")

if st.session_state.pki is not None:
    pki = st.session_state.pki
    trust = [pki.root_cert]
    
    st.subheader("Certificates in the Chain")
    
    def display_cert(name, cert):
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        iss = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        st.markdown(f"**{name}**")
        st.text(f"Subject: {cn}\nIssuer: {iss}\nSerial: {cert.serial_number}\nValid from: {cert.not_valid_before_utc.strftime('%Y-%m-%d')} to {cert.not_valid_after_utc.strftime('%Y-%m-%d')}")
        st.text(f"Signature (preview): {cert.signature.hex()[:24]}...")

    col1, col2, col3 = st.columns(3)
    with col1:
        display_cert("Root CA", pki.root_cert)
    with col2:
        display_cert("Intermediate CA", pki.inter_cert)
    with col3:
        display_cert("End-User Cert", pki.leaf_cert)

    st.divider()
    st.subheader("Validation Scenarios")
    
    scenario = st.selectbox(
        "Select a test scenario:",
        [
            "1. Valid chain",
            "2. Tampered end-user certificate",
            "3. Intermediate signed by an impostor",
            "4. Root not in trust store",
            "5. Expired validation time (400 days in future)",
            "6. Missing intermediate",
            "7. End-user cert abused as a CA"
        ]
    )

    if st.button("Validate"):
        leaf_cert = pki.leaf_cert
        intermediates = [pki.inter_cert]
        trust_store = trust
        at_time = None

        # Apply the chosen scenario
        if scenario.startswith("2"):
            leaf_cert = tamper(pki.leaf_cert)
        elif scenario.startswith("3"):
            evil_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            evil_name = make_name("Evil Root CA")
            evil_root = issue_cert(evil_name, evil_key, evil_name, evil_key, is_ca=True, path_length=1)
            fake_inter = issue_cert(pki.inter_cert.subject, pki.inter_key, pki.root_cert.subject, evil_key, is_ca=True, path_length=0)
            intermediates = [fake_inter]
        elif scenario.startswith("4"):
            trust_store = []
        elif scenario.startswith("5"):
            at_time = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=400)
        elif scenario.startswith("6"):
            intermediates = []
        elif scenario.startswith("7"):
            sub_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            sub_cert = issue_cert(make_name("sub.example.com"), sub_key, pki.leaf_cert.subject, pki.leaf_key, is_ca=False)
            leaf_cert = sub_cert
            intermediates = [pki.leaf_cert, pki.inter_cert]

        result = validate_chain(leaf_cert, intermediates, trust_store, at=at_time)

        if result.valid:
            st.success("Result: Chain is VALID")
        else:
            st.error("Result: Chain is INVALID")
            
        # Draw a simple graph indicating pass/fail at the nodes based on the scenario
        # This is purely visual for the demo
        root_color = "red" if scenario.startswith("4") else "green"
        inter_color = "red" if scenario.startswith("3") or scenario.startswith("6") else "green"
        user_color = "red" if scenario.startswith("2") or scenario.startswith("5") or scenario.startswith("7") else "green"

        if scenario.startswith("6"):
            graph = f'''
                digraph G {{
                    node [shape=box, style=filled, fontname="Helvetica"];
                    Root [label="Root CA", fillcolor="{root_color}"];
                    User [label="End-user (Alice)", fillcolor="{user_color}"];
                    Root -> User [style=dashed, label="Missing link"];
                }}
            '''
        elif scenario.startswith("7"):
            graph = f'''
                digraph G {{
                    node [shape=box, style=filled, fontname="Helvetica"];
                    Root [label="Root CA", fillcolor="{root_color}"];
                    Inter [label="Intermediate CA", fillcolor="{inter_color}"];
                    User [label="End-user (Alice)\\nCA=FALSE", fillcolor="{user_color}"];
                    Sub [label="Sub (Abused)", fillcolor="red"];
                    Root -> Inter;
                    Inter -> User;
                    User -> Sub;
                }}
            '''
        else:
            graph = f'''
                digraph G {{
                    node [shape=box, style=filled, fontname="Helvetica"];
                    Root [label="Root CA", fillcolor="{root_color}"];
                    Inter [label="Intermediate CA", fillcolor="{inter_color}"];
                    User [label="End-user (Alice)", fillcolor="{user_color}"];
                    
                    Root -> Inter;
                    Inter -> User;
                }}
            '''
            
        st.graphviz_chart(graph)

        st.markdown("### Validation Step Log")
        for line in result.log:
            if line.startswith("FAILURE:"):
                st.error(line)
            elif line.startswith("RESULT:"):
                st.markdown(f"**{line}**")
            elif "VERIFIED" in line or "OK" in line or "TRUSTED" in line:
                st.success(line)
            else:
                st.info(line)
