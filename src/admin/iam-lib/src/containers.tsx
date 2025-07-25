import {
    List,
    Datagrid,
    TextField,
    EmailField,
    Edit,
    SimpleForm,
    TextInput,
    Create,
} from 'react-admin';

export const ContainerList = () => (
    <List title="Containers">
        <Datagrid rowClick="edit">
            <TextField source="node" />
            <TextField source="hostname" />
            <TextField source="hostname" />
            <TextField source="memory" />
            <TextField source="cores" />
            <TextField source="ostype" />
            <TextField source="arch" />
            {/* <TextField source="network" /> */}
        </Datagrid>
    </List>
);
export const ContainerEdit = () => (
    <Edit title="Edit Container">
        <SimpleForm>
            <TextInput source="node" />
            <TextInput source="hostname" />
            <TextInput source="hostname" />
            <TextInput source="memory" />
            <TextInput source="cores" />
            <TextInput source="ostype" />
            <TextInput source="arch" />
        </SimpleForm>
    </Edit>
);
