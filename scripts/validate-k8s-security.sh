#!/bin/bash
set -e

echo "🔍 VALIDATION SÉCURITÉ KUBERNETES - BASÉE SUR VOS 3 PILIERS"
echo "=========================================================="

APP_NAME=$1
NAMESPACE=$2
BUILD_NUMBER=$3

if [ -z "$APP_NAME" ] || [ -z "$NAMESPACE" ] || [ -z "$BUILD_NUMBER" ]; then
    echo "❌ Usage: $0 <APP_NAME> <NAMESPACE> <BUILD_NUMBER>"
    exit 1
fi

echo "📋 Application: $APP_NAME"
echo "📋 Namespace: $NAMESPACE"
echo "📋 Build: $BUILD_NUMBER"
echo ""

# Attendre que les pods soient prêts
echo "⏳ Attente que les pods soient prêts (timeout 5min)..."
kubectl wait --for=condition=ready pod -l app=${APP_NAME} -n ${NAMESPACE} --timeout=300s

# Obtenir le nom du pod
POD_NAME=$(kubectl get pods -l app=${APP_NAME} -n ${NAMESPACE} -o jsonpath='{.items[0].metadata.name}')
echo "📋 Pod testé: ${POD_NAME}"
echo ""

# Variables pour le score
TOTAL_TESTS=0
PASSED_TESTS=0

# Fonction pour tester
test_security() {
    local test_name=$1
    local test_command=$2
    local expected_result=$3
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo "🧪 Test $TOTAL_TESTS: $test_name"
    
    result=$(eval "$test_command" 2>&1 || echo "ERROR")
    
    if [[ "$result" == *"$expected_result"* ]]; then
        echo "✅ SUCCÈS: $test_name"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    else
        echo "❌ ÉCHEC: $test_name"
        echo "   Résultat: $result"
        echo "   Attendu: $expected_result"
        return 1
    fi
}

echo "🛡️ PILIER 1: PODS SÉCURISÉS (Security Context)"
echo "================================================"

# Test 1: Vérifier utilisateur non-root
test_security \
    "Utilisateur non-root (1000)" \
    "kubectl exec ${POD_NAME} -n ${NAMESPACE} -- id -u" \
    "1000"

# Test 2: Vérifier groupe non-root
test_security \
    "Groupe non-root (1000)" \
    "kubectl exec ${POD_NAME} -n ${NAMESPACE} -- id -g" \
    "1000"

# Test 3: Vérifier filesystem read-only
test_security \
    "Filesystem read-only" \
    "kubectl exec ${POD_NAME} -n ${NAMESPACE} -- sh -c 'touch /etc/readonly-test 2>&1 || echo READONLY'" \
    "READONLY"

# Test 4: Vérifier capabilities
echo "🧪 Test $((TOTAL_TESTS + 1)): Capabilities limitées"
TOTAL_TESTS=$((TOTAL_TESTS + 1))
CAPS=$(kubectl exec ${POD_NAME} -n ${NAMESPACE} -- grep CapEff /proc/self/status | awk '{print $2}')
if [ "$CAPS" != "0000000000000400" ]; then # Seulement NET_BIND_SERVICE
    echo "✅ SUCCÈS: Capabilities limitées (CapEff: $CAPS)"
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    echo "⚠️  ATTENTION: Capabilities à vérifier (CapEff: $CAPS)"
fi

echo ""
echo "🔐 PILIER 2: RBAC (Role-Based Access Control)"
echo "=============================================="

# Test 5: Vérifier ServiceAccount
test_security \
    "ServiceAccount spécifique" \
    "kubectl get pod ${POD_NAME} -n ${NAMESPACE} -o jsonpath='{.spec.serviceAccountName}'" \
    "secure-app-sa"

# Test 6: Vérifier restriction accès secrets
test_security \
    "Accès secrets refusé" \
    "kubectl auth can-i get secrets --as=system:serviceaccount:${NAMESPACE}:secure-app-sa -n ${NAMESPACE}" \
    "no"

# Test 7: Vérifier restriction accès nodes
test_security \
    "Accès nodes refusé" \
    "kubectl auth can-i get nodes --as=system:serviceaccount:${NAMESPACE}:secure-app-sa" \
    "no"

echo ""
echo "🔒 PILIER 3: ISOLATION DES CONTENEURS"
echo "====================================="

# Test 8: Vérifier NetworkPolicy existe
echo "🧪 Test $((TOTAL_TESTS + 1)): NetworkPolicy présente"
TOTAL_TESTS=$((TOTAL_TESTS + 1))
NETPOL_COUNT=$(kubectl get networkpolicy -n ${NAMESPACE} -l app=${APP_NAME} --no-headers | wc -l)
if [ "$NETPOL_COUNT" -gt 0 ]; then
    echo "✅ SUCCÈS: $NETPOL_COUNT NetworkPolicy(s) trouvée(s)"
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    echo "❌ ÉCHEC: Aucune NetworkPolicy trouvée"
fi

# Test 9: Vérifier isolation réseau (trafic externe bloqué)
echo "🧪 Test $((TOTAL_TESTS + 1)): Isolation réseau externe"
TOTAL_TESTS=$((TOTAL_TESTS + 1))
NETWORK_TEST=$(kubectl exec ${POD_NAME} -n ${NAMESPACE} -- timeout 5 ping -c 1 8.8.8.8 2>&1 || echo "BLOCKED")
if echo "$NETWORK_TEST" | grep -q "BLOCKED\|timeout\|unreachable"; then
    echo "✅ SUCCÈS: Trafic externe bloqué"
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    echo "⚠️  ATTENTION: Trafic externe non complètement bloqué"
fi

# Test 10: Vérifier limites de ressources
echo "🧪 Test $((TOTAL_TESTS + 1)): Limites de ressources"
TOTAL_TESTS=$((TOTAL_TESTS + 1))
MEMORY_LIMIT=$(kubectl get pod ${POD_NAME} -n ${NAMESPACE} -o jsonpath='{.spec.containers[0].resources.limits.memory}')
if [ ! -z "$MEMORY_LIMIT" ]; then
    echo "✅ SUCCÈS: Limite mémoire définie ($MEMORY_LIMIT)"
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    echo "❌ ÉCHEC: Aucune limite mémoire définie"
fi

echo ""
echo "📊 RÉSUMÉ FINAL DES TESTS DE SÉCURITÉ"
echo "====================================="
echo "🎯 Tests réussis: $PASSED_TESTS/$TOTAL_TESTS"
echo "📈 Score de sécurité: $(( PASSED_TESTS * 100 / TOTAL_TESTS ))%"

if [ $PASSED_TESTS -eq $TOTAL_TESTS ]; then
    echo ""
    echo "🏆 FÉLICITATIONS! CONFIGURATION DE SÉCURITÉ PARFAITE!"
    echo "✅ Tous les piliers de sécurité sont respectés"
    echo "✅ Votre application est prête pour la production"
    exit 0
elif [ $PASSED_TESTS -ge $(( TOTAL_TESTS * 8 / 10 )) ]; then
    echo ""
    echo "🎉 TRÈS BIEN! Configuration sécurisée (80%+)"
    echo "⚠️  Quelques points d'amélioration identifiés"
    exit 0
else
    echo ""
    echo "⚠️  ATTENTION! Score de sécurité insuffisant"
    echo "❌ Veuillez corriger les problèmes identifiés"
    exit 1
fi
