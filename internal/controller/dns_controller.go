// Package controller implements the reconciler that synchronizes all HTTP Routes into
// AdGuard Home DNS rewrite rules.
package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gravity182/gateway-dns-operator/internal/adguard"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// AdguardRewriteClient allows to communicate with AdGuard Home rewrite control API.
type AdguardRewriteClient interface {
	ListRewrites(context.Context) ([]adguard.RewriteEntry, error)
	AddRewrite(context.Context, string, string) error
	UpdateRewrite(context.Context, adguard.RewriteEntry, adguard.RewriteEntry) error
	DeleteRewrite(context.Context, string, string) error
}

// DNSController is a reconciler that synchronizes all HTTP Routes into
// AdGuard Home DNS rewrite rules.
type DNSController struct {
	client.Client
	rewriteClient AdguardRewriteClient
}

// NewDNSController creates a new DNSController.
func NewDNSController(c client.Client, rewriteClient AdguardRewriteClient) *DNSController {
	return &DNSController{
		Client:        c,
		rewriteClient: rewriteClient,
	}
}

// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gateways,verbs=get;list;watch

// Reconcile synchronizes rewrite rules with the desired state
// derived from the HTTP Routes.
func (r *DNSController) Reconcile(
	ctx context.Context,
	_ ctrl.Request,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	logger.Info("Started reconciliation")

	currentState, err := buildCurrentState(ctx, r.rewriteClient)
	if err != nil {
		logger.Error(err, "Could not build current state")
		return ctrl.Result{}, err
	}
	logger.Info("Built current entries", "state", currentState)

	desiredState, err := buildDesiredState(ctx, r.Client)
	if err != nil {
		logger.Error(err, "Could not build desired state")
		return ctrl.Result{}, err
	}
	logger.Info("Built desired state", "state", desiredState)

	if err := reconcileAdguard(ctx, r.rewriteClient, desiredState, currentState); err != nil {
		logger.Error(err, "Could not reconcile adguard rewrite rules")
		return ctrl.Result{}, err
	}
	logger.Info("Successfully reconciled adguard rewrite rules")

	// periodically check the state
	return ctrl.Result{RequeueAfter: 10 * time.Minute}, nil
}

func reconcileAdguard(ctx context.Context, c AdguardRewriteClient, desired, current map[string]string) error {
	logger := log.FromContext(ctx)

	// prune deleted hostnames
	for domain, answer := range current {
		if _, keep := desired[domain]; keep {
			continue
		}

		// domain no longer exists
		if err := c.DeleteRewrite(ctx, domain, answer); err != nil {
			logger.Error(err, "Could not delete stale rewrite rule", "domain", domain, "answer", answer)
			return err
		}
		logger.Info("Deleted stale rewrite rule", "domain", domain, "answer", answer)
	}

	for domain, answer := range desired {
		currentAnswer, found := current[domain]
		if !found {
			// new rule
			if err := c.AddRewrite(ctx, domain, answer); err != nil {
				logger.Error(err, "Could not add rewrite rule", "domain", domain, "answer", answer)
				return err
			}
			logger.Info("Added rewrite rule", "domain", domain, "answer", answer)
			continue
		}
		// rule didn't change, skip
		if answer == currentAnswer {
			continue
		}

		// update existing rule
		oldEntry := adguard.RewriteEntry{Domain: domain, Answer: currentAnswer}
		newEntry := adguard.RewriteEntry{Domain: domain, Answer: answer}
		if err := c.UpdateRewrite(ctx, oldEntry, newEntry); err != nil {
			logger.Error(err, "Could not update rewrite rule", "oldEntry", oldEntry, "newEntry", newEntry)
			return err
		}
		logger.Info("Updated rewrite rule", "oldEntry", oldEntry, "newEntry", newEntry)
	}

	return nil
}

func buildCurrentState(ctx context.Context, c AdguardRewriteClient) (map[string]string, error) {
	rewrites, err := c.ListRewrites(ctx)
	if err != nil {
		return nil, err
	}

	state := make(map[string]string, len(rewrites))
	for _, rewrite := range rewrites {
		state[rewrite.Domain] = rewrite.Answer
	}
	return state, nil
}

func buildDesiredState(ctx context.Context, c client.Client) (map[string]string, error) {
	logger := log.FromContext(ctx)

	var routes gatewayv1.HTTPRouteList
	// TODO: filter routes by successful state
	if err := c.List(ctx, &routes); err != nil {
		return nil, fmt.Errorf("list httproutes: %w", err)
	}

	state := make(map[string]string)
	gateways := make(map[types.NamespacedName]gatewayv1.Gateway)
	for _, route := range routes.Items {
		parentRefKey, ok := findParentRef(route)
		if !ok {
			logger.Info("Route has no valid parent refs", "route", client.ObjectKeyFromObject(&route))
			continue
		}

		gateway, found := gateways[parentRefKey]
		if !found {
			if err := c.Get(ctx, parentRefKey, &gateway); err != nil {
				return nil, fmt.Errorf("get gateway %s: %w", parentRefKey, err)
			}
			gateways[parentRefKey] = gateway
		}

		vip := parseCiliumVIPAnnotation(gateway)
		if vip == "" {
			logger.Info("Gateway has no Cilium VIP annotation", "gateway", parentRefKey)
			continue
		}

		for _, hostname := range route.Spec.Hostnames {
			state[string(hostname)] = vip
		}
	}

	return state, nil
}

func parseCiliumVIPAnnotation(gateway gatewayv1.Gateway) string {
	annotations := gateway.Spec.Infrastructure.Annotations
	vip, ok := annotations["lbipam.cilium.io/ips"]
	if !ok {
		return ""
	}
	return string(vip)
}

func findParentRef(route gatewayv1.HTTPRoute) (types.NamespacedName, bool) {
	for _, parentRef := range route.Spec.ParentRefs {
		// nil kind and group are acceptable
		if parentRef.Kind != nil && *parentRef.Kind != "Gateway" {
			continue
		}
		if parentRef.Group != nil && *parentRef.Group != "gateway.networking.k8s.io" {
			continue
		}
		if !strings.HasPrefix(string(parentRef.Name), "envoy-") {
			continue
		}

		namespace := route.Namespace
		if parentRef.Namespace != nil {
			namespace = string(*parentRef.Namespace)
		}
		name := string(parentRef.Name)
		return types.NamespacedName{
			Namespace: namespace,
			Name:      name,
		}, true
	}
	return types.NamespacedName{}, false
}

// SetupWithManager allows to register this controller with a controller-runtime manager.
func (r *DNSController) SetupWithManager(mgr ctrl.Manager) error {
	enqueueFunc := handler.EnqueueRequestsFromMapFunc(func(_ context.Context, _ client.Object) []reconcile.Request {
		return []reconcile.Request{
			{NamespacedName: types.NamespacedName{
				Namespace: "network",
				Name:      "adguard-rewrites",
			}},
		}
	})
	return ctrl.NewControllerManagedBy(mgr).
		Watches(&gatewayv1.HTTPRoute{}, enqueueFunc).
		Watches(&gatewayv1.Gateway{}, enqueueFunc).
		Named("adguard-rewrites").
		Complete(r)
}
