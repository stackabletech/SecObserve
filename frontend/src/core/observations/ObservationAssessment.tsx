import PlaylistAddCheckIcon from "@mui/icons-material/PlaylistAddCheck";
import { Dialog, DialogContent, DialogTitle } from "@mui/material";
import { Fragment, useRef, useState } from "react";
import {
    ArrayInput,
    DateInput,
    FormDataConsumer,
    SimpleForm,
    SimpleFormIterator,
    useNotify,
    useRecordContext,
    useRefresh,
} from "react-admin";

import MarkdownEdit from "../../commons/custom_fields/MarkdownEdit";
import SmallButton from "../../commons/custom_fields/SmallButton";
import { ToolbarCancelSave } from "../../commons/custom_fields/ToolbarCancelSave";
import { validate_after_today, validate_required } from "../../commons/custom_validators";
import {
    justificationIsEnabledForStatus,
    remediationsAreEnabledForStatus,
    settings_vex_justification_style,
} from "../../commons/functions";
import { AutocompleteInputMedium, AutocompleteInputWide, TextInputWide } from "../../commons/layout/themes";
import { httpClient } from "../../commons/ra-data-django-rest-framework";
import { VEX_JUSTIFICATION_TYPE_CSAF_OPENVEX, VEX_JUSTIFICATION_TYPE_CYCLONEDX } from "../../commons/types";
import {
    OBSERVATION_CYCLONEDX_VEX_JUSTIFICATION_CHOICES,
    OBSERVATION_SEVERITY_CHOICES,
    OBSERVATION_STATUS_CHOICES,
    OBSERVATION_STATUS_RISK_ACCEPTED,
    OBSERVATION_VEX_JUSTIFICATION_CHOICES,
    OBSERVATION_VEX_REMEDIATION_CATEGORY_CHOICES,
} from "../types";

const ObservationAssessment = () => {
    const observation = useRecordContext();
    const dialogRef = useRef<HTMLDivElement>(null);
    const [comment, setComment] = useState<string | null>("");
    const [open, setOpen] = useState(false);
    const [status, setStatus] = useState(observation?.current_status);
    const justificationEnabled = justificationIsEnabledForStatus(status);
    const remediationsEnabled = remediationsAreEnabledForStatus(status);
    const refresh = useRefresh();
    const notify = useNotify();

    const observationUpdate = async (data: any) => {
        let local_comment = comment;
        if (local_comment === "") {
            local_comment = null;
        }
        const patch = {
            severity: data.current_severity,
            status: data.current_status,
            vex_justification: justificationEnabled ? data.current_vex_justification : "",
            vex_remediations: remediationsEnabled ? data.current_vex_remediations : "",
            comment: local_comment,
            risk_acceptance_expiry_date: data.risk_acceptance_expiry_date,
        };

        httpClient(window.__RUNTIME_CONFIG__.API_BASE_URL + "/observations/" + data.id + "/assessment/", {
            method: "PATCH",
            body: JSON.stringify(patch),
        })
            .then(() => {
                refresh();
                notify("Observation updated", {
                    type: "success",
                });
            })
            .catch((error) => {
                notify(error.message, {
                    type: "warning",
                });
            });

        setOpen(false);
    };

    const handleClose = (event: object, reason: string) => {
        if (reason && reason == "backdropClick") return;
        setOpen(false);
    };

    const handleCancel = () => setOpen(false);
    const handleOpen = () => setOpen(true);

    return (
        <Fragment>
            <SmallButton title="Assessment" onClick={handleOpen} icon={<PlaylistAddCheckIcon />} />
            <Dialog ref={dialogRef} open={open} onClose={handleClose} maxWidth={"xl"}>
                <DialogTitle>Observation Assessment</DialogTitle>
                <DialogContent>
                    <SimpleForm
                        onSubmit={observationUpdate}
                        toolbar={<ToolbarCancelSave onClick={handleCancel} alwaysEnable={true} />}
                    >
                        <AutocompleteInputMedium
                            source="current_severity"
                            choices={OBSERVATION_SEVERITY_CHOICES}
                            validate={validate_required}
                            label="Severity"
                        />
                        <AutocompleteInputMedium
                            source="current_status"
                            choices={OBSERVATION_STATUS_CHOICES}
                            validate={validate_required}
                            label="Status"
                            onChange={(e) => setStatus(e)}
                        />
                        {remediationsEnabled && (
                            <ArrayInput source="current_vex_remediations" defaultValue={""} label="VEX remediations">
                                <SimpleFormIterator disableReordering inline>
                                    <AutocompleteInputMedium
                                        source="category"
                                        label=""
                                        choices={OBSERVATION_VEX_REMEDIATION_CATEGORY_CHOICES}
                                    />
                                    <TextInputWide source="text" multiline={true} minRows={3} />
                                </SimpleFormIterator>
                            </ArrayInput>
                        )}
                        {justificationEnabled &&
                            settings_vex_justification_style() === VEX_JUSTIFICATION_TYPE_CSAF_OPENVEX && (
                                <AutocompleteInputWide
                                    source="current_vex_justification"
                                    label="VEX justification"
                                    choices={OBSERVATION_VEX_JUSTIFICATION_CHOICES}
                                />
                            )}
                        {justificationEnabled &&
                            settings_vex_justification_style() === VEX_JUSTIFICATION_TYPE_CYCLONEDX && (
                                <AutocompleteInputWide
                                    source="current_vex_justification"
                                    label="VEX justification"
                                    choices={OBSERVATION_CYCLONEDX_VEX_JUSTIFICATION_CHOICES}
                                />
                            )}
                        <FormDataConsumer>
                            {({ formData }) =>
                                formData.current_status &&
                                formData.current_status == OBSERVATION_STATUS_RISK_ACCEPTED &&
                                formData.product_data.risk_acceptance_expiry_date_calculated && (
                                    <DateInput
                                        source="risk_acceptance_expiry_date"
                                        label="Risk acceptance expiry date"
                                        defaultValue={formData.product_data.risk_acceptance_expiry_date_calculated}
                                        validate={validate_after_today()}
                                    />
                                )
                            }
                        </FormDataConsumer>
                        <MarkdownEdit
                            initialValue=""
                            setValue={setComment}
                            label="Comment"
                            overlayContainer={dialogRef.current ?? null}
                            maxLength={4096}
                        />
                    </SimpleForm>
                </DialogContent>
            </Dialog>
        </Fragment>
    );
};

export default ObservationAssessment;
