import { Stack } from "@mui/material";
import { Labeled, useRecordContext } from "react-admin";

import MarkdownField from "../../commons/custom_fields/MarkdownField";
import TextUrlField from "../../commons/custom_fields/TextUrlField";

const ObservationShowDescriptionRecommendation = () => {
    const observation = useRecordContext();
    return (
        <Stack spacing={2}>
            {observation && observation.description != "" && (
                <Labeled sx={{ paddingTop: 2 }}>
                    <MarkdownField content={observation.description} label="Description" />
                </Labeled>
            )}
            {observation && observation.recommendation != "" && (
                <Labeled>
                    <MarkdownField content={observation.recommendation} label="Recommendation" />
                </Labeled>
            )}
            {observation && observation.duplicates && observation.duplicates.length > 0 && (
                <Labeled label="Duplicates">
                    <Stack direction="row" spacing={2}>
                        {observation.duplicates.map((duplicate: any) => (
                            <TextUrlField
                                text={duplicate.id}
                                url={"#/observations/" + duplicate.id + "/show"}
                                key={duplicate.id}
                            />
                        ))}
                    </Stack>
                </Labeled>
            )}
        </Stack>
    );
};

export default ObservationShowDescriptionRecommendation;
