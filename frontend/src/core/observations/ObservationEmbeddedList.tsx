import { Stack } from "@mui/material";
import { Fragment, useEffect } from "react";
import {
    AutocompleteInput,
    BooleanField,
    ChipField,
    DatagridConfigurable,
    FilterButton,
    FilterForm,
    FunctionField,
    Identifier,
    ListContextProvider,
    NullableBooleanInput,
    NumberField,
    ReferenceInput,
    SelectColumnsButton,
    TextField,
    TextInput,
    TopToolbar,
    useListController,
} from "react-admin";
import { useNavigate } from "react-router";

import { PERMISSION_OBSERVATION_ASSESSMENT, PERMISSION_OBSERVATION_DELETE } from "../../access_control/types";
import { CustomPagination } from "../../commons/custom_fields/CustomPagination";
import { SeverityField } from "../../commons/custom_fields/SeverityField";
import { humanReadableDate } from "../../commons/functions";
import { AutocompleteInputMedium } from "../../commons/layout/themes";
import { getSettingListSize } from "../../commons/user_settings/functions";
import {
    AGE_CHOICES,
    OBSERVATION_SEVERITY_CHOICES,
    OBSERVATION_STATUS_CHOICES,
    OBSERVATION_STATUS_OPEN,
    Observation,
    PURL_TYPE_CHOICES,
    Product,
} from "../types";
import ObservationBulkAssessment from "./ObservationBulkAssessment";
import ObservationBulkDeleteButton from "./ObservationBulkDeleteButton";
import ObservationExpand from "./ObservationExpand";
import { IDENTIFIER_OBSERVATION_EMBEDDED_LIST, setListIdentifier } from "./functions";

function listFilters(product: Product) {
    const filters = [];
    if (product && product.has_branches) {
        filters.push(
            <ReferenceInput
                source="branch"
                reference="branches"
                sort={{ field: "name", order: "ASC" }}
                filter={{ product: product.id }}
                alwaysOn
            >
                <AutocompleteInputMedium optionText="name" label="Branch / Version" />
            </ReferenceInput>
        );
    }
    filters.push(<TextInput source="title" alwaysOn />);
    filters.push(
        <AutocompleteInput source="current_severity" label="Severity" choices={OBSERVATION_SEVERITY_CHOICES} alwaysOn />
    );
    filters.push(
        <AutocompleteInput source="current_status" label="Status" choices={OBSERVATION_STATUS_CHOICES} alwaysOn />
    );
    if (product && product.has_services) {
        filters.push(
            <ReferenceInput
                source="origin_service"
                reference="services"
                sort={{ field: "name", order: "ASC" }}
                filter={{ product: product.id }}
                alwaysOn
            >
                <AutocompleteInputMedium label="Service" optionText="name" />
            </ReferenceInput>
        );
    }

    if (product && product.has_component) {
        filters.push(<TextInput source="origin_component_name_version" label="Component" alwaysOn />);
        filters.push(
            <AutocompleteInput
                source="origin_component_purl_type"
                label="Component type"
                choices={PURL_TYPE_CHOICES}
                alwaysOn
            />
        );
    }
    if (product && product.has_docker_image) {
        filters.push(<TextInput source="origin_docker_image_name_tag_short" label="Container" alwaysOn />);
    }
    if (product && product.has_endpoint) {
        filters.push(<TextInput source="origin_endpoint_hostname" label="Host" alwaysOn />);
    }
    if (product && product.has_source) {
        filters.push(<TextInput source="origin_source_file" label="Source" alwaysOn />);
    }
    if (product && product.has_cloud_resource) {
        filters.push(<TextInput source="origin_cloud_qualified_resource" label="Cloud resource" alwaysOn />);
    }
    if (product && product.has_kubernetes_resource) {
        filters.push(<TextInput source="origin_kubernetes_qualified_resource" label="Kubernetes resource" alwaysOn />);
    }

    filters.push(<TextInput source="scanner" alwaysOn />);
    filters.push(<AutocompleteInputMedium source="age" choices={AGE_CHOICES} alwaysOn />);
    filters.push(<TextInput source="upload_filename" label="Filename" />);
    filters.push(<TextInput source="api_configuration_name" label="API configuration" />);
    if (product && product.has_potential_duplicates) {
        filters.push(<NullableBooleanInput source="has_potential_duplicates" label="Duplicates" alwaysOn />);
    }
    if (product && product.observation_log_approvals > 0) {
        filters.push(<NullableBooleanInput source="has_pending_assessment" label="Pending assessment" alwaysOn />);
    }
    filters.push(<TextInput source="origin_component_location" label="Component location" />);
    filters.push(<NullableBooleanInput source="patch_available" label="Patch available" alwaysOn />);
    filters.push(<NullableBooleanInput source="exploit_available" label="Exploit available" alwaysOn />);
    filters.push(<NullableBooleanInput source="in_vulncheck_kev" label="Listed in Vulncheck KEV" alwaysOn />);

    return filters;
}

const ShowObservations = (id: any) => {
    return "../../../../observations/" + id + "/show";
};

type ObservationsEmbeddedListProps = {
    product: any;
};

const BulkActionButtons = (product: any) => (
    <Fragment>
        {product.product.permissions.includes(PERMISSION_OBSERVATION_ASSESSMENT) && (
            <ObservationBulkAssessment product={product.product} />
        )}
        {product.product.permissions.includes(PERMISSION_OBSERVATION_DELETE) && (
            <ObservationBulkDeleteButton product={product.product} />
        )}
    </Fragment>
);

const ListActions = (product: any) => (
    <TopToolbar>
        <FilterButton filters={listFilters(product)} />
        <SelectColumnsButton preferenceKey="observations.embedded" />
    </TopToolbar>
);

const ObservationsEmbeddedList = ({ product }: ObservationsEmbeddedListProps) => {
    setListIdentifier(IDENTIFIER_OBSERVATION_EMBEDDED_LIST);

    const navigate = useNavigate();
    function get_observations_url(branch_id: Identifier): string {
        return `?displayedFilters=%7B%7D&filter=%7B%22current_status%22%3A%22Open%22%2C%22branch%22%3A${branch_id}%7D&order=ASC&sort=current_severity`;
    }
    useEffect(() => {
        const current_product_id = localStorage.getItem("observationembeddedlist.product");
        if (current_product_id == null || Number(current_product_id) !== product.id) {
            localStorage.removeItem("RaStore.observations.embedded");
            localStorage.setItem("observationembeddedlist.product", product.id);
            navigate(get_observations_url(product.repository_default_branch));
        }
    }, [product, navigate]);

    const listContext = useListController({
        filter: { product: Number(product.id) },
        perPage: 25,
        resource: "observations",
        sort: { field: "current_severity", order: "ASC" },
        filterDefaultValues: { current_status: OBSERVATION_STATUS_OPEN, branch: product.repository_default_branch },
        disableSyncWithLocation: false,
        storeKey: "observations.embedded",
    });

    if (listContext.isLoading) {
        return <div>Loading...</div>;
    }

    return (
        <ListContextProvider value={listContext}>
            <div style={{ width: "100%" }}>
                <Stack direction="row" spacing={2} justifyContent="center" alignItems="flex-end">
                    <FilterForm filters={listFilters(product)} />
                    <ListActions product={product} />
                </Stack>
                <DatagridConfigurable
                    size={getSettingListSize()}
                    sx={{ width: "100%" }}
                    rowClick={ShowObservations}
                    omit={["scanner_name", "stackable_score", "has_potential_duplicates"]}
                    bulkActionButtons={
                        product &&
                        (product.permissions.includes(PERMISSION_OBSERVATION_ASSESSMENT) ||
                            product.permissions.includes(PERMISSION_OBSERVATION_DELETE)) && (
                            <BulkActionButtons product={product} />
                        )
                    }
                    preferenceKey="observations.embedded"
                    resource="observations"
                    expand={<ObservationExpand />}
                    expandSingle
                >
                    {product && product.has_branches && <TextField source="branch_name" label="Branch / Version" />}
                    <TextField source="title" />
                    <SeverityField label="Severity" source="current_severity" />
                    <ChipField source="current_status" label="Status" />
                    {product && product.has_component && <NumberField source="epss_score" label="EPSS" />}
                    {product && product.has_services && <TextField source="origin_service_name" label="Service" />}
                    {product && product.has_component && (
                        <TextField
                            source="origin_component_name_version"
                            label="Component"
                            sx={{ wordBreak: "break-word" }}
                        />
                    )}
                    {product && product.has_docker_image && (
                        <TextField
                            source="origin_docker_image_name_tag_short"
                            label="Container"
                            sx={{ wordBreak: "break-word" }}
                        />
                    )}
                    {product && product.has_endpoint && (
                        <TextField source="origin_endpoint_hostname" label="Host" sx={{ wordBreak: "break-word" }} />
                    )}
                    {product && product.has_source && (
                        <TextField source="origin_source_file" label="Source" sx={{ wordBreak: "break-word" }} />
                    )}
                    {product && product.has_cloud_resource && (
                        <TextField
                            source="origin_cloud_qualified_resource"
                            label="Cloud resource"
                            sx={{ wordBreak: "break-word" }}
                        />
                    )}
                    {product && product.has_kubernetes_resource && (
                        <TextField
                            source="origin_kubernetes_qualified_resource"
                            label="Kubernetes resource"
                            sx={{ wordBreak: "break-word" }}
                        />
                    )}
                    <TextField
                        source="origin_component_location"
                        label="Component location"
                        sx={{ wordBreak: "break-word" }}
                    />
                    <TextField source="scanner_name" label="Scanner" />
                    <FunctionField<Observation>
                        label="Age"
                        sortBy="last_observation_log"
                        render={(record) => (record ? humanReadableDate(record.last_observation_log) : "")}
                    />
                    {product && product.has_potential_duplicates && (
                        <BooleanField source="has_potential_duplicates" label="Dupl." />
                    )}
                    <BooleanField source="patch_available" label="Patch" />
                </DatagridConfigurable>
                <CustomPagination />
            </div>
        </ListContextProvider>
    );
};

export default ObservationsEmbeddedList;
