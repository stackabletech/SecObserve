import { Stack } from "@mui/material";
import { Fragment } from "react";
import {
    AutocompleteInput,
    Datagrid,
    DateField,
    FilterForm,
    ListContextProvider,
    ReferenceInput,
    ResourceContextProvider,
    TextField,
    TextInput,
    useListController,
} from "react-admin";

import { PERMISSION_OBSERVATION_LOG_APPROVAL } from "../../access_control/types";
import { CustomPagination } from "../../commons/custom_fields/CustomPagination";
import { AutocompleteInputMedium, AutocompleteInputWide } from "../../commons/layout/themes";
import { getSettingListSize } from "../../commons/user_settings/functions";
import { ASSESSMENT_STATUS_NEEDS_APPROVAL } from "../types";
import { OBSERVATION_SEVERITY_CHOICES, OBSERVATION_STATUS_CHOICES } from "../types";
import AssessmentBulkApproval from "./AssessmentBulkApproval";
import AssessmentDeleteApproval from "./AssessmentDeleteApproval";

const BulkActionButtons = ({ product }: any) => {
    return (
        <Fragment>
            {(!product || (product && product.permissions.includes(PERMISSION_OBSERVATION_LOG_APPROVAL))) && (
                <Stack direction="row" spacing={2} alignItems="center">
                    <AssessmentBulkApproval />
                    <AssessmentDeleteApproval />
                </Stack>
            )}
        </Fragment>
    );
};

function listFilters(product: any) {
    const filters = [];
    if (!product) {
        filters.push(
            <ReferenceInput
                source="product"
                reference="products"
                sort={{ field: "name", order: "ASC" }}
                queryOptions={{ meta: { api_resource: "product_names" } }}
                alwaysOn
            >
                <AutocompleteInputMedium optionText="name" />
            </ReferenceInput>
        );
    }
    if (!product) {
        filters.push(
            <ReferenceInput
                source="product_group"
                reference="product_groups"
                sort={{ field: "name", order: "ASC" }}
                queryOptions={{ meta: { api_resource: "product_group_names" } }}
                alwaysOn
            >
                <AutocompleteInputMedium optionText="name" />
            </ReferenceInput>
        );
    }
    if (!product) {
        filters.push(
            <ReferenceInput
                source="branch"
                reference="branches"
                sort={{ field: "name", order: "ASC" }}
                queryOptions={{ meta: { api_resource: "branch_names" } }}
                alwaysOn
            >
                <AutocompleteInputWide optionText="name_with_product" label="Branch / Version" />
            </ReferenceInput>,
            <TextInput source="branch_name" label="Branch / Version name" alwaysOn />
        );
    }

    if (product && product.has_branches) {
        filters.push(
            <ReferenceInput
                source="branch"
                reference="branches"
                queryOptions={{ meta: { api_resource: "branch_names" } }}
                sort={{ field: "name", order: "ASC" }}
                filter={{ product: product.id }}
                alwaysOn
            >
                <AutocompleteInputMedium optionText="name" label="Branch / Version" />
            </ReferenceInput>,
            <TextInput source="branch_name" label="Branch / Version name" alwaysOn />
        );
    }

    filters.push(<TextInput source="observation_title" label="Observation title" alwaysOn />);

    if (!product || (product && product.has_component)) {
        filters.push(<TextInput source="origin_component_name_version" label="Component" alwaysOn />);
    }

    filters.push(
        <ReferenceInput source="user" reference="users" sort={{ field: "full_name", order: "ASC" }} alwaysOn>
            <AutocompleteInputMedium optionText="full_name" />
        </ReferenceInput>,
        <AutocompleteInput source="severity" label="Severity" choices={OBSERVATION_SEVERITY_CHOICES} alwaysOn />,
        <AutocompleteInput source="status" label="Status" choices={OBSERVATION_STATUS_CHOICES} alwaysOn />
    );
    return filters;
}

type ObservationLogApprovalListProps = {
    product?: any;
};

const ObservationLogApprovalList = ({ product }: ObservationLogApprovalListProps) => {
    let filter = {};
    filter = { assessment_status: ASSESSMENT_STATUS_NEEDS_APPROVAL };
    if (product) {
        filter = { ...filter, product: Number(product.id) };
    }
    let storeKey = "observation_logs.approval";
    if (product) {
        storeKey = "observation_logs.approvalproduct";
    }
    const listContext = useListController({
        filter: filter,
        perPage: 25,
        resource: "observation_logs",
        sort: { field: "created", order: "ASC" },
        disableSyncWithLocation: true,
        storeKey: storeKey,
    });

    if (listContext.isLoading) {
        return <div>Loading...</div>;
    }

    const ShowObservationLogs = (id: any) => {
        return "../../../../observation_logs/" + id + "/show";
    };

    if (product) {
        localStorage.setItem("observationlogapprovallistproduct", "true");
        localStorage.removeItem("observationlogapprovallist");
    } else {
        localStorage.setItem("observationlogapprovallist", "true");
        localStorage.removeItem("observationlogapprovallistproduct");
    }
    localStorage.removeItem("observationlogembeddedlist");

    return (
        <ResourceContextProvider value="observation_logs">
            <ListContextProvider value={listContext}>
                <div style={{ width: "100%" }}>
                    <FilterForm filters={listFilters(product)} />
                    <Datagrid
                        size={getSettingListSize()}
                        sx={{ width: "100%" }}
                        bulkActionButtons={
                            !product ||
                            (product && product.permissions.includes(PERMISSION_OBSERVATION_LOG_APPROVAL)) ? (
                                <BulkActionButtons product={product} />
                            ) : (
                                false
                            )
                        }
                        rowClick={ShowObservationLogs}
                        resource="observation_logs"
                    >
                        <DateField locales="de-DE" source="created" showTime />
                        {!product && <TextField source="observation_data.product_data.name" label="Product" />}
                        {!product && <TextField source="observation_data.branch_name" label="Branch / Version" />}
                        {(!product || (product && product.has_component)) && (
                            <TextField
                                source="observation_data.origin_component_name_version"
                                label="Component"
                                sx={{ wordBreak: "break-word" }}
                            />
                        )}
                        <TextField source="observation_data.title" label="Observation" />
                        <TextField source="user_full_name" label="User" />
                        <TextField source="severity" emptyText="---" />
                        <TextField source="status" emptyText="---" />
                    </Datagrid>
                    <CustomPagination />
                </div>
            </ListContextProvider>
        </ResourceContextProvider>
    );
};

export default ObservationLogApprovalList;
