import { Fragment } from "react";
import {
    AutocompleteInput,
    BooleanField,
    ChipField,
    DatagridConfigurable,
    FilterButton,
    FilterForm,
    FunctionField,
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

import observations from ".";
import { CustomPagination } from "../../commons/custom_fields/CustomPagination";
import { SeverityField } from "../../commons/custom_fields/SeverityField";
import { humanReadableDate } from "../../commons/functions";
import ListHeader from "../../commons/layout/ListHeader";
import { AutocompleteInputMedium, NullableBooleanInputWide } from "../../commons/layout/themes";
import { getSettingListSize } from "../../commons/user_settings/functions";
import {
    AGE_CHOICES,
    OBSERVATION_SEVERITY_CHOICES,
    OBSERVATION_STATUS_CHOICES,
    OBSERVATION_STATUS_OPEN,
    Observation,
    PURL_TYPE_CHOICES,
} from "../types";
import ObservationBulkAssessment from "./ObservationBulkAssessment";
import ObservationExpand from "./ObservationExpand";
import { IDENTIFIER_OBSERVATION_LIST, setListIdentifier } from "./functions";

const listFilters = () => [
    <ReferenceInput source="product" reference="products" sort={{ field: "name", order: "ASC" }} alwaysOn>
        <AutocompleteInput optionText="name" />
    </ReferenceInput>,
    <ReferenceInput source="product_group" reference="product_groups" sort={{ field: "name", order: "ASC" }} alwaysOn>
        <AutocompleteInput optionText="name" />
    </ReferenceInput>,
    <ReferenceInput source="branch" reference="branches" sort={{ field: "name", order: "ASC" }} alwaysOn>
        <AutocompleteInputMedium optionText="name_with_product" label="Branch / Version" />
    </ReferenceInput>,
    <TextInput source="branch_name" label="Branch / Version name" />,
    <TextInput source="title" alwaysOn />,
    <AutocompleteInput source="current_severity" label="Severity" choices={OBSERVATION_SEVERITY_CHOICES} alwaysOn />,
    <AutocompleteInput source="current_status" label="Status" choices={OBSERVATION_STATUS_CHOICES} alwaysOn />,
    // <ReferenceInput label="Service" source="origin_service" reference="services" sort={{ field: "name", order: "ASC" }}>
    //     <AutocompleteInputWide label="Service" optionText="name_with_product" />
    // </ReferenceInput>,
    <TextInput source="origin_component_name_version" label="Component" />,
    <TextInput source="origin_docker_image_name_tag_short" label="Container" />,
    <TextInput source="origin_component_location" label="Component location" />,
    // <TextInput source="origin_endpoint_hostname" label="Host" />,
    // <TextInput source="origin_source_file" label="Source" />,
    // <TextInput source="origin_cloud_qualified_resource" label="Resource" />,
    <TextInput source="scanner" />,
    <AutocompleteInputMedium source="age" choices={AGE_CHOICES} />,
    <NullableBooleanInput source="has_potential_duplicates" label="Duplicates" />,
    <NullableBooleanInputWide source="patch_available" label="Patch available" alwaysOn />,
    <NullableBooleanInputWide source="exploit_available" label="Exploit available" alwaysOn />,
    <NullableBooleanInputWide source="in_vulncheck_kev" label="Listed in Vulncheck KEV" alwaysOn />,
    <NullableBooleanInputWide source="has_pending_assessment" label="Pending assessment" alwaysOn />,
    <AutocompleteInput
        source="origin_component_purl_type"
        label="Component type"
        choices={PURL_TYPE_CHOICES}
        alwaysOn
    />,
];

const BulkActionButtons = () => (
    <Fragment>
        <ObservationBulkAssessment product={null} />
    </Fragment>
);

const ObservationList = () => {
    setListIdentifier(IDENTIFIER_OBSERVATION_LIST);
    const listContext = useListController({
        filterDefaultValues: { current_status: OBSERVATION_STATUS_OPEN },
        perPage: 25,
        resource: "observations",
        sort: { field: "current_severity", order: "ASC" },
        storeKey: "observations.list",
        disableSyncWithLocation: false,
    });

    if (listContext.isLoading) {
        return <div>Loading...</div>;
    }

    // hack to sync parameters to location URL if they are loaded from the store
    if (listContext.sort && !document.location.hash.match(/#\/observations.*\?/)) {
        listContext.setSort(listContext.sort);
    }

    return (
        <Fragment>
            <ListHeader icon={observations.icon} title="Observations" />
            <ListContextProvider value={listContext}>
                <div style={{ width: "100%", marginTop: 1 }}>
                    <TopToolbar>
                        <FilterForm filters={listFilters()} />
                        <FilterButton filters={listFilters()} />
                        <SelectColumnsButton preferenceKey="observations.list" />
                    </TopToolbar>
                    <DatagridConfigurable
                        size={getSettingListSize()}
                        omit={["scanner_name", "stackable_score", "has_potential_duplicates"]}
                        rowClick="show"
                        bulkActionButtons={<BulkActionButtons />}
                        preferenceKey="observations.list"
                        expand={<ObservationExpand />}
                        expandSingle
                    >
                        <TextField source="product_data.name" label="Product" />
                        <TextField source="product_data.product_group_name" label="Group" />
                        <TextField source="branch_name" label="Branch / Version" />
                        <TextField source="title" />
                        <SeverityField source="current_severity" />
                        <ChipField source="current_status" label="Status" />
                        <NumberField source="epss_score" label="EPSS" />
                        <NumberField source="stackable_score" label="Stackable Score" />
                        {/* <TextField source="origin_service_name" label="Service" /> */}
                        <TextField
                            source="origin_component_name_version"
                            label="Component"
                            sx={{ wordBreak: "break-word" }}
                        />
                        <TextField
                            source="origin_docker_image_name_tag_short"
                            label="Container"
                            sx={{ wordBreak: "break-word" }}
                        />
                        <TextField
                            source="origin_component_location"
                            label="Component location"
                            sx={{ wordBreak: "break-word" }}
                        />
                        {/* <TextField source="origin_endpoint_hostname" label="Host" /> */}
                        {/* <TextField source="origin_source_file" label="Source" /> */}
                        {/* <TextField source="origin_cloud_qualified_resource" label="Resource" />, */}
                        <TextField source="scanner_name" label="Scanner" />
                        <FunctionField<Observation>
                            label="Age"
                            sortBy="last_observation_log"
                            render={(record) => (record ? humanReadableDate(record.last_observation_log) : "")}
                        />
                        <BooleanField source="has_potential_duplicates" label="Dupl." />
                        <BooleanField source="patch_available" label="Patch" />
                    </DatagridConfigurable>
                    <CustomPagination />
                </div>
            </ListContextProvider>
        </Fragment>
    );
};

export default ObservationList;
