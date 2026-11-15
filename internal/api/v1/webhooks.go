package v1

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/thep1ckaxe91/stripe-lite/internal/payments"
	"github.com/thep1ckaxe91/stripe-lite/internal/webhooks"
)

type webhookNotImplementedResponse ProblemDocument

func (response webhookNotImplementedResponse) VisitListWebhookEndpointsResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusNotImplemented)

	return json.NewEncoder(w).Encode(response)
}

func (response webhookNotImplementedResponse) VisitCreateWebhookEndpointResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusNotImplemented)

	return json.NewEncoder(w).Encode(response)
}

// ListWebhookEndpoints handles GET /webhook-endpoints
func (s *Server) ListWebhookEndpoints(
	ctx context.Context,
	request ListWebhookEndpointsRequestObject,
) (ListWebhookEndpointsResponseObject, error) {
	const instance = "/webhook-endpoints"

	// Get merchant identity from authenticated context.
	principal, ok := payments.PrincipalFrom(ctx)
	if !ok {
		return ListWebhookEndpoints401ApplicationProblemPlusJSONResponse(
			newWebhookProblem(
				http.StatusUnauthorized,
				"unauthorized",
				"Valid authentication credentials are required.",
				instance,
			),
		), nil
	}

	// Handle unavailable database-backed service.
	if s.webhooks == nil {
		return ListWebhookEndpoints500ApplicationProblemPlusJSONResponse(
			newWebhookProblem(
				http.StatusInternalServerError,
				"internal",
				"Webhook persistence is unavailable.",
				instance,
			),
		), nil
	}

	// Retrieve endpoints belonging to the authenticated merchant.
	endpoints, err := s.webhooks.List(ctx, principal.MerchantID)
	if err != nil {
		return ListWebhookEndpoints500ApplicationProblemPlusJSONResponse(
			newWebhookProblem(
				http.StatusInternalServerError,
				"internal",
				"The webhook endpoints could not be retrieved.",
				instance,
			),
		), nil
	}

	// Convert service models to safe API response models.
	data := make([]WebhookEndpointResponse, 0, len(endpoints))
	for _, endpoint := range endpoints {
		data = append(data, webhookModel(endpoint))
	}

	return ListWebhookEndpoints200JSONResponse{
		Data: data,
	}, nil
}

func newWebhookProblem(status int, code, detail, instance string) ProblemDocument {
	return ProblemDocument{
		Type:     "https://api.stripe-lite.internal/errors/" + code,
		Title:    http.StatusText(status),
		Status:   int32(status),
		Detail:   &detail,
		Instance: &instance,
	}
}

func webhookModel(endpoint webhooks.Endpoint) WebhookEndpointResponse {
	events := make([]WebhookEventType, len(endpoint.Events))
	for i, event := range endpoint.Events {
		events[i] = WebhookEventType(event)
	}

	return WebhookEndpointResponse{
		Id:        endpoint.ID,
		Url:       endpoint.URL,
		Events:    events,
		Status:    WebhookEndpointResponseStatus(endpoint.Status),
		CreatedAt: endpoint.CreatedAt,
	}
}

// CreateWebhookEndpoint handles POST /webhook-endpoints
// Configures HTTPS delivery target and event subscriptions with signing secrets.

func (s *Server) CreateWebhookEndpoint(
	ctx context.Context,
	request CreateWebhookEndpointRequestObject,
) (CreateWebhookEndpointResponseObject, error) {
	const instance = "/webhook-endpoints"

	// Merchant identity must come from authenticated context.
	principal, ok := payments.PrincipalFrom(ctx)
	if !ok {
		return CreateWebhookEndpoint401ApplicationProblemPlusJSONResponse(
			newWebhookProblem(
				http.StatusUnauthorized,
				"unauthorized",
				"Valid authentication credentials are required.",
				instance,
			),
		), nil
	}

	// Handle requests without a JSON body.
	if request.Body == nil {
		return CreateWebhookEndpoint400ApplicationProblemPlusJSONResponse(
			newWebhookProblem(
				http.StatusBadRequest,
				"invalid-request",
				"A request body is required.",
				instance,
			),
		), nil
	}

	// Database-backed service may be unavailable in smoke mode.
	if s.webhooks == nil {
		return CreateWebhookEndpoint500ApplicationProblemPlusJSONResponse(
			newWebhookProblem(
				http.StatusInternalServerError,
				"internal",
				"Webhook persistence is unavailable.",
				instance,
			),
		), nil
	}

	// Convert generated OpenAPI event types to service types.
	events := make([]string, len(request.Body.Events))
	for i, event := range request.Body.Events {
		events[i] = string(event)
	}

	endpoint, secret, err := s.webhooks.Create(
		ctx,
		principal.MerchantID,
		request.Body.Url,
		events,
	)

	if err != nil {
		if errors.Is(err, webhooks.ErrInvalidEndpoint) {
			return CreateWebhookEndpoint400ApplicationProblemPlusJSONResponse(
				newWebhookProblem(
					http.StatusBadRequest,
					"invalid-request",
					"Invalid webhook URL or event subscriptions.",
					instance,
				),
			), nil
		}

		// Handle duplicate webhook destination URL.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) &&
			pgErr.Code == "23505" &&
			pgErr.ConstraintName == "webhook_endpoints_merchant_url_unique_idx" {

			return CreateWebhookEndpoint409ApplicationProblemPlusJSONResponse(
				newWebhookProblem(
					http.StatusConflict,
					"conflict",
					"A webhook endpoint for this URL already exists.",
					instance,
				),
			), nil
		}

		return CreateWebhookEndpoint500ApplicationProblemPlusJSONResponse(
			newWebhookProblem(
				http.StatusInternalServerError,
				"internal",
				"Webhook endpoint could not be created.",
				instance,
			),
		), nil
	}

	responseEvents := make([]WebhookEventType, len(endpoint.Events))
	for i, event := range endpoint.Events {
		responseEvents[i] = WebhookEventType(event)
	}

	return CreateWebhookEndpoint201JSONResponse{
		Id:        endpoint.ID,
		Url:       endpoint.URL,
		Events:    responseEvents,
		Status:    CreateWebhookEndpointResponseStatus(endpoint.Status),
		Secret:    secret,
		CreatedAt: endpoint.CreatedAt,
	}, nil
}

// Response visitors for the remaining Webhook operations.
// All return HTTP 501 with an RFC 7807 Problem Document.

func (response webhookNotImplementedResponse) VisitGetWebhookEndpointResponse(w http.ResponseWriter) error {
	return response.VisitListWebhookEndpointsResponse(w)
}

func (response webhookNotImplementedResponse) VisitUpdateWebhookEndpointResponse(w http.ResponseWriter) error {
	return response.VisitListWebhookEndpointsResponse(w)
}

func (response webhookNotImplementedResponse) VisitDeleteWebhookEndpointResponse(w http.ResponseWriter) error {
	return response.VisitListWebhookEndpointsResponse(w)
}

func (response webhookNotImplementedResponse) VisitRotateWebhookSecretResponse(w http.ResponseWriter) error {
	return response.VisitListWebhookEndpointsResponse(w)
}

// GetWebhookEndpoint handles GET /webhook-endpoints/{id}
func (s *Server) GetWebhookEndpoint(
	ctx context.Context,
	request GetWebhookEndpointRequestObject,
) (GetWebhookEndpointResponseObject, error) {
	instance := "/webhook-endpoints/" + request.Id

	// Get merchant identity from authenticated context.
	principal, ok := payments.PrincipalFrom(ctx)
	if !ok {
		return GetWebhookEndpoint401ApplicationProblemPlusJSONResponse(
			newWebhookProblem(
				http.StatusUnauthorized,
				"unauthorized",
				"Valid authentication credentials are required.",
				instance,
			),
		), nil
	}

	// Handle unavailable webhook service.
	if s.webhooks == nil {
		return GetWebhookEndpoint500ApplicationProblemPlusJSONResponse(
			newWebhookProblem(
				http.StatusInternalServerError,
				"internal",
				"Webhook persistence is unavailable.",
				instance,
			),
		), nil
	}

	// Retrieve the endpoint belonging to this merchant.
	endpoint, err := s.webhooks.Get(
		ctx,
		principal.MerchantID,
		request.Id,
	)

	if err != nil {
		// Do not reveal whether another merchant owns the endpoint.
		if errors.Is(err, pgx.ErrNoRows) ||
			errors.Is(err, webhooks.ErrInvalidEndpoint) {
			return GetWebhookEndpoint404ApplicationProblemPlusJSONResponse(
				newWebhookProblem(
					http.StatusNotFound,
					"not-found",
					"The requested webhook endpoint was not found.",
					instance,
				),
			), nil
		}

		return GetWebhookEndpoint500ApplicationProblemPlusJSONResponse(
			newWebhookProblem(
				http.StatusInternalServerError,
				"internal",
				"The webhook endpoint could not be retrieved.",
				instance,
			),
		), nil
	}

	// Convert to a safe response without the signing secret.
	return GetWebhookEndpoint200JSONResponse(
		webhookModel(endpoint),
	), nil
}

// UpdateWebhookEndpoint handles PATCH /webhook-endpoints/{id}
func (s *Server) UpdateWebhookEndpoint(
	ctx context.Context,
	request UpdateWebhookEndpointRequestObject,
) (UpdateWebhookEndpointResponseObject, error) {
	instance := "/webhook-endpoints/" + request.Id

	// Get merchant identity from authenticated context.
	principal, ok := payments.PrincipalFrom(ctx)
	if !ok {
		return UpdateWebhookEndpoint401ApplicationProblemPlusJSONResponse(
			newWebhookProblem(
				http.StatusUnauthorized,
				"unauthorized",
				"Valid authentication credentials are required.",
				instance,
			),
		), nil
	}

	// Validate the request body.
	if request.Body == nil {
		return UpdateWebhookEndpoint400ApplicationProblemPlusJSONResponse(
			newWebhookProblem(
				http.StatusBadRequest,
				"invalid-request",
				"A request body is required.",
				instance,
			),
		), nil
	}

	// Check endpoint ID.
	if !strings.HasPrefix(request.Id, "we_") {
		return UpdateWebhookEndpoint404ApplicationProblemPlusJSONResponse(
			newWebhookProblem(
				http.StatusNotFound,
				"not-found",
				"The requested webhook endpoint was not found.",
				instance,
			),
		), nil
	}

	if s.webhooks == nil {
		return UpdateWebhookEndpoint500ApplicationProblemPlusJSONResponse(
			newWebhookProblem(
				http.StatusInternalServerError,
				"internal",
				"Webhook persistence is unavailable.",
				instance,
			),
		), nil
	}

	// Convert OpenAPI request fields to Service parameters.
	params := webhooks.UpdateParams{
		URL: request.Body.Url,
	}

	if request.Body.Events != nil {
		events := make([]string, len(*request.Body.Events))
		for i, event := range *request.Body.Events {
			events[i] = string(event)
		}
		params.Events = &events
	}

	if request.Body.Status != nil {
		status := string(*request.Body.Status)
		params.Status = &status
	}

	// Update the endpoint for the authenticated merchant.
	endpoint, err := s.webhooks.Update(
		ctx,
		principal.MerchantID,
		request.Id,
		params,
	)

	if err != nil {
		// Invalid update payload.
		if errors.Is(err, webhooks.ErrInvalidEndpoint) {
			return UpdateWebhookEndpoint400ApplicationProblemPlusJSONResponse(
				newWebhookProblem(
					http.StatusBadRequest,
					"invalid-request",
					"Invalid webhook update parameters.",
					instance,
				),
			), nil
		}

		// Endpoint does not exist or belongs to another merchant.
		if errors.Is(err, pgx.ErrNoRows) {
			return UpdateWebhookEndpoint404ApplicationProblemPlusJSONResponse(
				newWebhookProblem(
					http.StatusNotFound,
					"not-found",
					"The requested webhook endpoint was not found.",
					instance,
				),
			), nil
		}

		// The destination URL is already registered by this merchant.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) &&
			pgErr.Code == "23505" &&
			pgErr.ConstraintName == "webhook_endpoints_merchant_url_unique_idx" {
			return UpdateWebhookEndpoint400ApplicationProblemPlusJSONResponse(
				newWebhookProblem(
					http.StatusBadRequest,
					"invalid-request",
					"A webhook endpoint for this URL already exists.",
					instance,
				),
			), nil
		}

		// Unexpected database or server error.
		return UpdateWebhookEndpoint500ApplicationProblemPlusJSONResponse(
			newWebhookProblem(
				http.StatusInternalServerError,
				"internal",
				"The webhook endpoint could not be updated.",
				instance,
			),
		), nil
	}

	// Return the updated endpoint without its signing secret.
	return UpdateWebhookEndpoint200JSONResponse(
		webhookModel(endpoint),
	), nil
}

// DeleteWebhookEndpoint handles DELETE /webhook-endpoints/{id}
func (s *Server) DeleteWebhookEndpoint(
	ctx context.Context,
	request DeleteWebhookEndpointRequestObject,
) (DeleteWebhookEndpointResponseObject, error) {
	instance := "/webhook-endpoints/" + request.Id

	// Get merchant identity from authenticated context.
	principal, ok := payments.PrincipalFrom(ctx)
	if !ok {
		return DeleteWebhookEndpoint401ApplicationProblemPlusJSONResponse(
			newWebhookProblem(
				http.StatusUnauthorized,
				"unauthorized",
				"Valid authentication credentials are required.",
				instance,
			),
		), nil
	}

	// Reject invalid endpoint IDs as not found.
	if !strings.HasPrefix(request.Id, "we_") {
		return DeleteWebhookEndpoint404ApplicationProblemPlusJSONResponse(
			newWebhookProblem(
				http.StatusNotFound,
				"not-found",
				"The requested webhook endpoint was not found.",
				instance,
			),
		), nil
	}

	// Handle unavailable database-backed service.
	if s.webhooks == nil {
		return DeleteWebhookEndpoint500ApplicationProblemPlusJSONResponse(
			newWebhookProblem(
				http.StatusInternalServerError,
				"internal",
				"Webhook persistence is unavailable.",
				instance,
			),
		), nil
	}

	// Delete only the endpoint belonging to this merchant.
	err := s.webhooks.Delete(
		ctx,
		principal.MerchantID,
		request.Id,
	)

	if err != nil {
		// Do not reveal whether another merchant owns the endpoint.
		if errors.Is(err, pgx.ErrNoRows) ||
			errors.Is(err, webhooks.ErrInvalidEndpoint) {
			return DeleteWebhookEndpoint404ApplicationProblemPlusJSONResponse(
				newWebhookProblem(
					http.StatusNotFound,
					"not-found",
					"The requested webhook endpoint was not found.",
					instance,
				),
			), nil
		}

		// Unexpected database or server error.
		return DeleteWebhookEndpoint500ApplicationProblemPlusJSONResponse(
			newWebhookProblem(
				http.StatusInternalServerError,
				"internal",
				"The webhook endpoint could not be deleted.",
				instance,
			),
		), nil
	}

	// Successful deletion returns HTTP 204 with an empty body.
	return DeleteWebhookEndpoint204Response{}, nil
}

// RotateWebhookSecret handles POST /webhook-endpoints/{id}/rotate-secret
func (s *Server) RotateWebhookSecret(
	ctx context.Context,
	request RotateWebhookSecretRequestObject,
) (RotateWebhookSecretResponseObject, error) {
	instance := "/webhook-endpoints/" + request.Id + "/rotate-secret"

	// Get merchant identity from authenticated context.
	principal, ok := payments.PrincipalFrom(ctx)
	if !ok {
		return RotateWebhookSecret401ApplicationProblemPlusJSONResponse(
			newWebhookProblem(
				http.StatusUnauthorized,
				"unauthorized",
				"Valid authentication credentials are required.",
				instance,
			),
		), nil
	}

	// Reject invalid endpoint IDs as not found.
	if !strings.HasPrefix(request.Id, "we_") {
		return RotateWebhookSecret404ApplicationProblemPlusJSONResponse(
			newWebhookProblem(
				http.StatusNotFound,
				"not-found",
				"The requested webhook endpoint was not found.",
				instance,
			),
		), nil
	}

	// Handle unavailable database-backed service.
	if s.webhooks == nil {
		return RotateWebhookSecret500ApplicationProblemPlusJSONResponse(
			newWebhookProblem(
				http.StatusInternalServerError,
				"internal",
				"Webhook persistence is unavailable.",
				instance,
			),
		), nil
	}

	// Generate and persist a new signing secret.
	secret, err := s.webhooks.RotateSecret(
		ctx,
		principal.MerchantID,
		request.Id,
	)

	if err != nil {
		// Do not reveal whether another merchant owns the endpoint.
		if errors.Is(err, pgx.ErrNoRows) ||
			errors.Is(err, webhooks.ErrInvalidEndpoint) {
			return RotateWebhookSecret404ApplicationProblemPlusJSONResponse(
				newWebhookProblem(
					http.StatusNotFound,
					"not-found",
					"The requested webhook endpoint was not found.",
					instance,
				),
			), nil
		}

		// Unexpected database or server error.
		return RotateWebhookSecret500ApplicationProblemPlusJSONResponse(
			newWebhookProblem(
				http.StatusInternalServerError,
				"internal",
				"The signing secret could not be rotated.",
				instance,
			),
		), nil
	}

	// Return the newly generated secret only after successful rotation.
	return RotateWebhookSecret200JSONResponse(
		RotateWebhookSecretResponse{
			Id:     request.Id,
			Secret: secret,
		},
	), nil
}
