import ChecklistIcon from "@mui/icons-material/Checklist";
import {
    AutocompleteInput,
    Datagrid,
    DateField,
    FilterForm,
    ListContextProvider,
    ReferenceField,
    ReferenceInput,
    TextField,
    TextInput,
    useListController,
} from "react-admin";
import { Fragment } from "react/jsx-runtime";

import { CustomPagination } from "../../commons/custom_fields/CustomPagination";
import { feature_vex_enabled } from "../../commons/functions";
import ListHeader from "../../commons/layout/ListHeader";
import { AutocompleteInputMedium, AutocompleteInputWide } from "../../commons/layout/themes";
import { getSettingListSize } from "../../commons/user_settings/functions";
import { ASSESSMENT_STATUS_NEEDS_APPROVAL } from "../types";
import { OBSERVATION_SEVERITY_CHOICES, OBSERVATION_STATUS_CHOICES } from "../types";
import AssessmentBulkApproval from "./AssessmentBulkApproval";

const BulkActionButtons = () => (
    <Fragment>
        <AssessmentBulkApproval />
    </Fragment>
);

function listFilters() {
    return [
        <TextInput source="observation_title" label="Observation title" alwaysOn />,
        <ReferenceInput source="user" reference="users" sort={{ field: "full_name", order: "ASC" }} alwaysOn>
            <AutocompleteInputMedium optionText="full_name" />
        </ReferenceInput>,
        <AutocompleteInput source="severity" label="Severity" choices={OBSERVATION_SEVERITY_CHOICES} alwaysOn />,
        <AutocompleteInput source="status" label="Status" choices={OBSERVATION_STATUS_CHOICES} alwaysOn />,
        <ReferenceInput source="product" reference="products" sort={{ field: "name", order: "ASC" }} alwaysOn>
            <AutocompleteInputMedium optionText="name" />
        </ReferenceInput>,
        <ReferenceInput
            source="product_group"
            reference="product_groups"
            sort={{ field: "name", order: "ASC" }}
            alwaysOn
        >
            <AutocompleteInputMedium optionText="name" />
        </ReferenceInput>,
        <ReferenceInput source="branch" reference="branches" sort={{ field: "name", order: "ASC" }} alwaysOn>
            <AutocompleteInputWide optionText="name_with_product" label="Branch / Version" />
        </ReferenceInput>,
        <TextInput source="branch_name" label="Branch / Version name" alwaysOn />,
        <TextInput source="origin_component_name_version" label="Component" alwaysOn />,
    ];
}


const ObservationLogApprovalList = () => {
    const listContext = useListController({
        filter: { assessment_status: ASSESSMENT_STATUS_NEEDS_APPROVAL },
        perPage: 25,
        resource: "observation_logs",
        sort: { field: "created", order: "ASC" },
        disableSyncWithLocation: true,
        storeKey: "observation_logs.approval",
    });

    if (listContext.isLoading) {
        return <div>Loading...</div>;
    }

    if (listContext.data === undefined) {
        listContext.data = [];
    }

    listContext.data.forEach((element: any) => {
        if (element.comment.length > 255) {
            element.comment_shortened = element.comment.substring(0, 255) + "...";
        } else {
            element.comment_shortened = element.comment;
        }
    });

    const ShowObservationLogs = (id: any) => {
        return "../../../../observation_logs/" + id + "/show";
    };

    localStorage.setItem("observationlogapprovallist", "true");
    localStorage.removeItem("observationlogembeddedlist");

    return (
        <Fragment>
            <ListHeader icon={ChecklistIcon} title="Reviews" />
            <ListContextProvider value={listContext}>
                <div style={{ width: "100%" }}>
                    <FilterForm filters={listFilters()} />
                    <Datagrid
                        size={getSettingListSize()}
                        sx={{ width: "100%" }}
                        bulkActionButtons={<BulkActionButtons />}
                        rowClick={ShowObservationLogs}
                    >
                        <DateField source="created" showTime />
                        <TextField source="user_full_name" label="User" />
                        <ReferenceField source="observation" reference="observations" link="show">
                            <TextField source="title" />
                        </ReferenceField>
                        <TextField source="product_name" label="Product" />
                        <TextField source="branch_name" label="Branch / Version" />
                        <TextField source="origin_component_name_version" label="Component" />
                        <TextField source="severity" emptyText="---" />
                        <TextField source="status" emptyText="---" />
                        {feature_vex_enabled() && (
                            <TextField label="VEX justification" source="vex_justification" emptyText="---" />
                        )}
                        <TextField source="comment_shortened" sortable={false} label="Comment" />
                    </Datagrid>
                    <CustomPagination />
                </div>
            </ListContextProvider>
        </Fragment>
    );
};

export default ObservationLogApprovalList;
