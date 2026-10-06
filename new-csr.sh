#!/usr/bin/env bash
#
# new-csr.sh - Génère une nouvelle clé privée et la CSR associée,
#              sans aucune question (sujet pré-rempli ci-dessous).
#
# Usage :
#   new-csr.sh [-t rsa|ec] [-b bits] [-o dossier] <fqdn> [san ...]
#
# Exemples :
#   new-csr.sh glpi.example.fr
#   new-csr.sh glpi.example.fr assistance.example.fr 10.0.0.12
#   new-csr.sh -t ec '*.example.fr' example.fr
#
set -euo pipefail

# --------------------------------------------------------------------
# Réponses pré-enregistrées : à adapter une fois pour toutes
# --------------------------------------------------------------------
C="FR"
ST="Ile-de-France"
L="Paris"
O="NosLand.com"
OU=""                   # vide = champ absent de la CSR
EMAIL="ssl@nosland.com"                # vide = champ absent de la CSR

KEY_TYPE="rsa"          # rsa | ec
RSA_BITS=2048
EC_CURVE="prime256v1"
OUT_BASE="${HOME}/ssl"  # un sous-dossier <nom>/<date-heure> est créé à chaque appel
# --------------------------------------------------------------------

usage() {
    cat >&2 <<EOF
Usage : $(basename "$0") [-t rsa|ec] [-b bits] [-o dossier] <fqdn> [san ...]

  -t  type de clé (défaut : ${KEY_TYPE})
  -b  taille de la clé RSA (défaut : ${RSA_BITS})
  -o  dossier de sortie (défaut : ${OUT_BASE})

Le premier nom est le CN ; il est ajouté automatiquement aux SAN.
Les noms suivants (DNS ou IP) sont ajoutés comme SAN supplémentaires.
EOF
    exit "${1:-1}"
}

while getopts ":t:b:o:h" opt; do
    case "$opt" in
        t) KEY_TYPE="$OPTARG" ;;
        b) RSA_BITS="$OPTARG" ;;
        o) OUT_BASE="$OPTARG" ;;
        h) usage 0 ;;
        *) usage 1 ;;
    esac
done
shift $((OPTIND - 1))
[ $# -ge 1 ] || usage 1

case "$KEY_TYPE" in
    rsa|ec) ;;
    *) echo "Type de clé inconnu : ${KEY_TYPE} (rsa ou ec)" >&2; exit 1 ;;
esac

command -v openssl >/dev/null || { echo "openssl introuvable" >&2; exit 1; }

CN="$1"
NAME="${CN/\*/wildcard}"                 # *.example.fr -> wildcard.example.fr
OUT_DIR="${OUT_BASE}/${NAME}/$(date +%Y%m%d-%H%M%S)"
KEY="${OUT_DIR}/${NAME}.key"
CSR="${OUT_DIR}/${NAME}.csr"
CNF="${OUT_DIR}/${NAME}.cnf"

umask 077                                # clé lisible par son propriétaire uniquement
mkdir -p "$OUT_DIR"

# --- Fichier de configuration OpenSSL (conservé comme trace) ---------
{
    cat <<EOF
[req]
prompt             = no
utf8               = yes
string_mask        = utf8only
default_md         = sha256
distinguished_name = dn
req_extensions     = ext

[dn]
C  = ${C}
ST = ${ST}
L  = ${L}
O  = ${O}
EOF
    if [ -n "$OU" ]; then echo "OU = ${OU}"; fi
    echo "CN = ${CN}"
    if [ -n "$EMAIL" ]; then echo "emailAddress = ${EMAIL}"; fi

    cat <<EOF

[ext]
subjectAltName = @san

[san]
EOF
    dns=0; ip=0
    declare -A seen=()
    for n in "$@"; do
        if [ -n "${seen[$n]:-}" ]; then continue; fi
        seen[$n]=1
        if [[ "$n" =~ ^[0-9]+(\.[0-9]+){3}$ || "$n" == *:* ]]; then
            ip=$((ip + 1));  echo "IP.${ip} = ${n}"
        else
            dns=$((dns + 1)); echo "DNS.${dns} = ${n}"
        fi
    done
} > "$CNF"

# --- Nouvelle clé privée ---------------------------------------------
if [ "$KEY_TYPE" = "rsa" ]; then
    openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:${RSA_BITS}" \
        -out "$KEY" 2>/dev/null \
        || { echo "Échec de la génération de la clé RSA" >&2; exit 1; }
else
    openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:${EC_CURVE}" \
        -pkeyopt ec_param_enc:named_curve -out "$KEY" 2>/dev/null \
        || { echo "Échec de la génération de la clé EC" >&2; exit 1; }
fi

# --- CSR ---------------------------------------------------------------
openssl req -new -config "$CNF" -key "$KEY" -out "$CSR"

# --- Contrôle et récapitulatif -----------------------------------------
openssl req -in "$CSR" -noout -verify >/dev/null 2>&1 \
    || { echo "La CSR générée est invalide" >&2; exit 1; }

echo "Clé    : ${KEY}"
echo "CSR    : ${CSR}"
echo "Sujet  : $(openssl req -in "$CSR" -noout -subject | sed 's/^subject= *//')"
echo "SAN    : $(openssl req -in "$CSR" -noout -text \
                 | grep -A1 'Subject Alternative Name' | tail -n1 | sed 's/^ *//')"
echo
cat "$CSR"
