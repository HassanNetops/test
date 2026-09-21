"""SNMPv3 polling configuration, using the standard device handler lifecycle.

One managed agent configuration per device; users_access is the complete user
list. Shell writes are experimental and require explicit _allow_shell opt-in.
"""

from __future__ import annotations

import copy
import logging
import re
from typing import Any, ClassVar

from scm_auto.exceptions import APIError, IntentSchemaError
from scm_auto.handlers.sdwan.devices._base import ElementChildHandler
from scm_auto.handlers.sdwan_base import _deep_merge, _strip_write_only
from scm_auto.models.intent import FieldChange, ResourceResult

logger = logging.getLogger(__name__)


class SnmpAgentHandler(ElementChildHandler):
    resource_path = (
        "/sdwan/v2.1/api/sites/{site_id}/elements/{element_id}/snmpagents"
    )
    resource_key = "snmp_agents"
    _write_only_fields: ClassVar[frozenset[str]] = frozenset({
        "v3_config.users_access[].auth_phrase",
        "v3_config.users_access[].enc_phrase",
    })
    _wire_fields: ClassVar[frozenset[str]] = frozenset({
        "id", "_etag", "description", "tags", "system_location",
        "system_contact", "v3_config",
    })
    _input_fields: ClassVar[frozenset[str]] = (_wire_fields - {"id", "_etag"}) | frozenset({
        "name", "site_id", "element_id", "_is_element_shell", "_allow_shell",
        "_update_secrets", "_plan_scope", "_intent_site_name", "_intent_device_name",
    })

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            return self.client.request(method, path, **kwargs)
        except APIError as exc:
            # Controller validation messages can echo submitted values. Retain
            # status + structured codes, never credential-bearing free text.
            body = exc.response_body
            errors = body.get("_error", []) if isinstance(body, dict) else []
            codes = [
                e["code"] for e in errors
                if isinstance(e, dict) and isinstance(e.get("code"), str)
                and re.fullmatch(r"[A-Z][A-Z0-9_]{0,100}", e["code"])
            ] if isinstance(errors, list) else []
            detail = ", ".join(codes) or "SNMP_API_ERROR"
            raise APIError(
                f"SNMP HTTP {exc.status_code}: {detail}", exc.status_code
            ) from None

    def _context(self, payload: dict[str, Any]) -> tuple[dict[str, Any], ResourceResult | None]:
        body = copy.deepcopy(payload)
        is_shell = body.pop("_is_element_shell", None)
        allow_shell = body.pop("_allow_shell", False)
        if type(is_shell) is not bool or type(allow_shell) is not bool:
            raise IntentSchemaError("SNMP requires boolean device state and shell opt-in")
        body["name"] = "snmp_agent"
        if is_shell and not allow_shell:
            detail = "SNMP deferred: shell support unverified; attach device or opt into lab shell test"
            logger.info(detail)
            return body, ResourceResult(
                name="snmp_agent", resource_type=self.resource_key,
                action="skipped", detail=detail,
            )
        return body, None

    @classmethod
    def validate(cls, payload: dict[str, Any], *, require_secrets: bool = False) -> None:
        """Accept only SNMPv3 authPriv/SHA/AES configuration and context."""
        if payload.keys() - cls._input_fields:
            raise IntentSchemaError("Unsupported field in SNMPv3-only configuration")
        v3 = payload.get("v3_config")
        if not isinstance(v3, dict) or v3.get("enabled") is not True:
            raise IntentSchemaError("SNMP requires v3_config.enabled=true")
        if v3.keys() - {"enabled", "users_access"}:
            raise IntentSchemaError("Unsupported field in SNMPv3 configuration")
        users = v3.get("users_access")
        if not isinstance(users, list) or not users:
            raise IntentSchemaError("SNMP requires a non-empty users_access list")
        names: set[str] = set()
        for user in users:
            if not isinstance(user, dict):
                raise IntentSchemaError("Invalid SNMP user entry")
            if user.keys() - {
                "user_name", "security_level", "auth_type", "enc_type",
                "auth_phrase", "enc_phrase", "engine_id",
            }:
                raise IntentSchemaError("Unsupported field in SNMPv3 user configuration")
            name = user.get("user_name")
            if not isinstance(name, str) or not name.strip() or name in names:
                raise IntentSchemaError("SNMP usernames must be non-empty and unique")
            names.add(name)
            if (user.get("security_level"), user.get("auth_type"), user.get("enc_type")) != (
                "PRIVATE", "SHA", "AES"
            ):
                raise IntentSchemaError("SNMP requires PRIVATE security with SHA/AES")
            if require_secrets:
                for field in ("auth_phrase", "enc_phrase"):
                    value = user.get(field)
                    if (
                        not isinstance(value, str) or not value.strip("*")
                        or value.startswith("_replace_from_env_")
                        or value in {"REPLACE_VIA_ENV", "REPLACE_VIA_SCRIPT_FROM_ENV"}
                    ):
                        raise IntentSchemaError(f"SNMP {field} requires a resolved secret")

    def _find_existing(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        path = self._build_path(payload)
        response = self._request("GET", path)
        if not isinstance(response, dict) or not isinstance(response.get("items"), list):
            raise IntentSchemaError("Unexpected SNMP list response; refusing to create")
        items = response["items"]
        if not items:
            return None
        if len(items) != 1 or not isinstance(items[0], dict) or not items[0].get("id"):
            raise IntentSchemaError("Expected one identifiable SNMP configuration; refusing ambiguous selection")
        config_id = items[0]["id"]
        current = self._request("GET", f"{path}/{config_id}")
        if not isinstance(current, dict) or current.get("id") != config_id:
            raise IntentSchemaError("Unexpected SNMP configuration response")
        # The API's shared agent object can contain unrelated configuration.
        # Only retain the fields this SNMPv3 handler owns.
        return {**self._strip_parent_ids(current), "name": "snmp_agent"}

    def _strip_parent_ids(self, payload: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in payload.items() if k in self._wire_fields}

    def create(self, payload: dict[str, Any]) -> dict[str, Any]:
        body = self._strip_parent_ids(payload)
        body.pop("id", None)
        body.pop("_etag", None)
        return self._request("POST", self._build_path(payload), json=body)

    def update(self, resource_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request(
            "PUT", f"{self._build_path(payload)}/{resource_id}",
            json=self._strip_parent_ids(payload),
        )

    def delete_by_id(self, resource_id: str, payload: dict[str, Any] | None = None) -> None:
        self._request("DELETE", f"{self._build_path(payload or {})}/{resource_id}")

    def _compute_changes(self, existing: dict[str, Any], desired: dict[str, Any]) -> dict[str, FieldChange]:
        def normalized(value: dict[str, Any]) -> dict[str, Any]:
            result = copy.deepcopy(value)
            if isinstance(result.get("tags"), list):
                result["tags"] = sorted(result["tags"])
            v3 = result.get("v3_config")
            if isinstance(v3, dict) and isinstance(v3.get("users_access"), list):
                v3["users_access"] = sorted(v3["users_access"], key=lambda u: u.get("user_name", ""))
            return result
        return super()._compute_changes(normalized(existing), normalized(desired))

    def check(self, payload: dict[str, Any]) -> ResourceResult:
        body, skipped = self._context(payload)
        if skipped is not None:
            return skipped
        self.validate(body)
        result = super().check(body)
        if self._should_rotate_secrets(body) and result.action in {"unchanged", "updated"}:
            result.action = "updated"
            result.detail = "Would update and rotate SNMP credentials"
        return result

    def ensure(self, payload: dict[str, Any]) -> ResourceResult:
        body, skipped = self._context(payload)
        if skipped is not None:
            return skipped
        self.validate(body)
        rotate = self._should_rotate_secrets(body)
        desired = self._prepare_body(self._resolve_refs(body))
        existing = self._find_existing(desired)
        action = "unchanged"
        if existing is None or self._needs_update(existing, desired) or rotate:
            self.validate(desired, require_secrets=True)
            if existing is None:
                self.create(desired)
                action = "created"
            else:
                if existing.get("_etag") is None:
                    raise IntentSchemaError("SNMP update requires the controller _etag")
                merged = _deep_merge(_strip_write_only(existing, self._write_only_fields), desired)
                # Never merge different users by list position or reuse masked
                # credentials. Each write supplies the complete desired users.
                merged["v3_config"] = copy.deepcopy(desired["v3_config"])
                self.update(existing["id"], merged)
                action = "updated"
        logger.info("SNMP agent %s", action)
        return ResourceResult(name="snmp_agent", resource_type=self.resource_key, action=action)

    def remove(self, payload: dict[str, Any]) -> ResourceResult:
        body, skipped = self._context(payload)
        return skipped if skipped is not None else super().remove(body)
