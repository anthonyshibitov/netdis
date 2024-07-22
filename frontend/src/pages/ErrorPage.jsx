import { useRouteError} from 'react-router-dom';

export default function ErrorPage() {
    const error = useRouteError();
    console.error(error)
    return (
        <>
            <h1>Whoops</h1>
            <h2>Error: {error.statusText || error.message}</h2>
        </>
    )
}